from __future__ import annotations

import ctypes
from contextlib import ExitStack, nullcontext
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_step


class BasicWorkflowContractTest(unittest.TestCase):
    def test_paths_csv_counts_and_interaction_exception_are_stable(self):
        report = Path("report-root")
        self.assertEqual(
            run_step.runtime_indexes_dir(report),
            report / run_step.RUNTIME_DIRNAME / run_step.RUNTIME_INDEXES_DIRNAME,
        )
        self.assertEqual(
            run_step.step5_query_index_path(report),
            report / run_step.RUNTIME_DIRNAME / run_step.RUNTIME_INDEXES_DIRNAME / run_step.STEP5_QUERY_INDEX_FILE,
        )

        with tempfile.TemporaryDirectory() as temporary:
            csv_path = Path(temporary) / "rows.csv"
            self.assertEqual(run_step.count_data_rows(csv_path), 0)
            csv_path.write_text("# generated\nname,value\na,1\n\nb,2\n", encoding="utf-8")
            self.assertEqual(run_step.count_data_rows(csv_path), 2)

        interaction = {"title": "补充输入", "reason_codes": ["MISSING"]}
        error = run_step.StepInteractionRequired(interaction)
        self.assertIs(error.interaction, interaction)
        self.assertEqual(str(error), "补充输入")

    def test_static_step_contracts_have_required_identity_fields(self):
        identity = run_step.build_step1_identity_response_properties()
        self.assertEqual(identity["manual_coord_overrides"]["type"], "array")
        self.assertIn("version", identity["manual_artifact_identities"]["items"]["required"])

        contract = run_step.build_step0_static_contract()
        self.assertEqual(contract["schema"], "java-upgrade-analyzer.step0-contract.v1")
        modes = {item["id"]: item for item in contract["input_modes"]}
        for mode in ("artifact_inputs", "checkout_build"):
            self.assertIn("application_source", modes[mode]["required_fields"])
            self.assertIn("target_module", modes[mode]["required_fields"])


class CoordinateNormalizationContractTest(unittest.TestCase):
    def test_coordinate_helpers_cover_exact_prefix_hint_and_path_matching(self):
        coords = ["com.acme:billing-api", "com.acme:orders", "org.other:billing"]
        self.assertEqual(run_step._validate_coord_or_prefix_or_empty(" com.acme ", "x"), "com.acme")
        self.assertEqual(run_step._filter_inferred_coords_by_prefix(coords, "com.acme"), coords[:2])
        self.assertEqual(
            run_step._filter_inferred_coords_by_prefix(coords, "com.acme:orders"),
            ["com.acme:orders"],
        )
        self.assertEqual(run_step._split_coord(" com.acme : billing-api "), ("com.acme", "billing-api"))
        self.assertEqual(run_step._split_coord("group-only"), ("group-only", ""))
        self.assertEqual(run_step._split_coord(""), ("", ""))
        self.assertEqual(run_step._norm_token("Billing_API-2"), "billingapi2")
        self.assertEqual(
            run_step._filter_inferred_coords_by_hint(coords, "ignored:billing-api", "/repo/unknown"),
            ["com.acme:billing-api"],
        )
        self.assertEqual(
            run_step._filter_inferred_coords_by_hint(coords, "unknown", "/repo/orders"),
            ["com.acme:orders"],
        )
        self.assertEqual(
            run_step._filter_inferred_coords_by_hint(["g:a"], "", "/repo"),
            ["g:a"],
        )

    def test_repository_expansion_is_exact_and_rejects_unmatched_hints(self):
        with patch.object(
            run_step, "infer_maven_coords", return_value=["g:a", "g:b"],
        ):
            self.assertEqual(
                run_step._expand_coord_path_by_repo("g:a", "/repo", "sources"),
                ["g:a=/repo"],
            )
            self.assertEqual(
                run_step._expand_coord_path_by_repo(
                    "", "/repo", "sources", expand_all_inferred=True,
                ),
                ["g:a=/repo", "g:b=/repo"],
            )
            with self.assertRaises(run_step.StepError):
                run_step._expand_coord_path_by_repo("g:missing", "/repo", "sources")

        with patch.object(run_step, "infer_maven_coords", return_value=[]):
            self.assertEqual(
                run_step._expand_coord_path_by_repo("g:a", "/repo", "sources"),
                ["g:a=/repo"],
            )
            with self.assertRaises(run_step.StepError):
                run_step._expand_coord_path_by_repo("group", "/repo", "sources")
            with self.assertRaises(run_step.StepError):
                run_step._expand_coord_path_by_repo("", "/repo", "sources")

    def test_coordinate_path_normalization_accepts_supported_shapes_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "repo"
            repository.mkdir()
            project = Path(temporary)
            with patch.object(
                run_step, "infer_maven_coords", return_value=["g:a"],
            ):
                self.assertEqual(
                    run_step.normalize_coord_path_items(
                        [str(repository)], project, "sources", allow_repo_inference=True,
                    ),
                    [f"g:a={repository.resolve()}"],
                )
                self.assertEqual(
                    run_step.normalize_coord_path_items(
                        {"g:a": str(repository)}, project, "sources",
                    ),
                    [f"g:a={repository.resolve()}"],
                )
            self.assertIsNone(
                run_step.normalize_coord_path_items(None, project, "sources")
            )
            for invalid in ("plain", [1], [{}]):
                with self.subTest(invalid=invalid), self.assertRaises(run_step.StepError):
                    run_step.normalize_coord_path_items(invalid, project, "sources")


class SourcePinningContractTest(unittest.TestCase):
    def test_semantic_and_persisted_paths_never_accept_escape_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            project.mkdir()
            configured = Path(temporary) / "configured"
            configured.mkdir()
            self.assertEqual(
                run_step._semantic_source_project_root(
                    {"current_source_project_dir": str(configured)}, project,
                ),
                configured.resolve(),
            )
            self.assertEqual(
                run_step._semantic_source_project_root({}, project), project.resolve(),
            )
            self.assertEqual(
                run_step._stable_path_from_project_relative(project, "src/main/java"),
                str((project / "src/main/java").resolve()),
            )
            self.assertEqual(
                run_step._stable_path_from_project_relative(project, "."),
                str(project.resolve()),
            )
            for invalid in ("../outside", "/absolute", "C:/outside"):
                with self.subTest(invalid=invalid), self.assertRaises(run_step.StepError):
                    run_step._stable_path_from_project_relative(project, invalid)

    def test_unpinned_discovery_is_discarded_without_overwriting_explicit_input(self):
        context = {
            "target_module": "app",
            "project_scope": {"status": "complete"},
            "source_dirs": ["/mutable/src"],
            "source_dirs_status": "detected",
            "tool": "maven",
            "base_tool": "maven",
            "current_tool": "maven",
        }
        discarded = run_step._discard_unpinned_local_source_discovery(context)
        self.assertEqual(discarded["project_scope"]["reason_codes"], ["current_source_not_pinned"])
        self.assertEqual(discarded["source_dirs"], [])
        self.assertEqual(discarded["tool"], "")

        explicit = dict(context, source_dirs_status="explicit", tool_explicit=True)
        preserved = run_step._discard_unpinned_local_source_discovery(explicit)
        self.assertEqual(preserved["source_dirs"], ["/mutable/src"])
        self.assertEqual(preserved["tool"], "maven")

    def test_project_scope_logicalization_marks_outside_roots_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            inside = project / "src" / "main" / "java"
            inside.mkdir(parents=True)
            outside = Path(temporary) / "outside"
            outside.mkdir()
            scope = {
                "status": "complete",
                "source_roots": [str(inside), str(outside)],
                "resource_roots": [],
                "missing_declared_roots": [],
                "candidate_module_details": [
                    {"module": "app", "module_dir": str(project)},
                    "legacy",
                ],
            }
            logical = run_step._logicalize_project_scope_paths(scope, project)
        self.assertEqual(logical["system_source"], ".")
        self.assertEqual(logical["source_roots"], ["src/main/java"])
        self.assertEqual(logical["status"], "partial")
        self.assertIn("pinned_source_root_outside_project", logical["reason_codes"])
        self.assertEqual(logical["candidate_module_details"][0]["module_dir"], ".")
        self.assertRegex(logical["scope_hash"], r"^[0-9a-f]{64}$")

    def test_git_root_resolution_has_success_and_fail_closed_paths(self):
        with patch.object(run_step, "run_cmd", return_value=("/repo\n", "", 0)):
            self.assertEqual(run_step._pinned_source_git_root("/repo/sub"), Path("/repo"))
        with patch.object(run_step, "run_cmd", return_value=("", "fatal", 1)):
            with self.assertRaises(run_step.StepError) as raised:
                run_step._pinned_source_git_root("/repo/sub")
        self.assertIn("PINNED_SOURCE_REPOSITORY_UNAVAILABLE", raised.exception.reason_codes)

    def test_pinned_workspace_maps_logical_roots_and_always_removes_worktree(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = root / "worktree"
            (worktree / "src/main/java").mkdir(parents=True)
            (worktree / "src/main/resources").mkdir(parents=True)
            context = {
                "current_resolved_commit": commit,
                "pinned_source_snapshot": {
                    "schema": run_step.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                    "commit": commit,
                    "project_path": ".",
                    "source_roots": ["src/main/java"],
                    "resource_roots": ["src/main/resources"],
                },
            }
            with patch.object(run_step, "_pinned_snapshot_matches_context", return_value=True), patch.object(
                run_step, "_step1_ref_repository", return_value=root,
            ), patch.object(run_step, "_pinned_source_git_root", return_value=root), patch.object(
                run_step, "create_detached_worktree", return_value=worktree,
            ), patch.object(run_step, "remove_detached_worktree") as remove:
                with run_step.materialize_pinned_source_workspace(context, root) as materialized:
                    self.assertEqual(materialized["project_root"], worktree.resolve())
                    self.assertEqual(materialized["source_dirs"], [str((worktree / "src/main/java").resolve())])
                    self.assertEqual(materialized["resource_dirs"], [str((worktree / "src/main/resources").resolve())])
            remove.assert_called_once()

        with self.assertRaises(run_step.StepError):
            with run_step.materialize_pinned_source_workspace({}, "."):
                pass

    def test_rebuild_without_immutable_commit_removes_stale_snapshot(self):
        rebuilt = run_step.rebuild_current_pinned_source_context(
            {"current_resolved_commit": "branch", "pinned_source_snapshot": {"stale": True}},
            ".",
        )
        self.assertNotIn("pinned_source_snapshot", rebuilt)

    def test_valid_pinned_snapshot_rehydrates_only_repository_relative_scope(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            project.mkdir()
            context = {
                "current_resolved_commit": commit,
                "target_module": "app",
                "active_maven_profiles": ["prod", "prod"],
                "current_source_project_dir": str(project),
                "pinned_source_snapshot": {
                    "schema": run_step.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                    "commit": commit,
                    "target_module": "app",
                    "active_maven_profiles": ["prod"],
                    "build_tool": "maven",
                    "source_roots": ["src/main/java", "src/main/java"],
                    "source_dirs_status": "detected",
                    "project_scope": {
                        "status": "complete",
                        "source_roots": ["src/main/java"],
                        "resource_roots": ["src/main/resources"],
                        "candidate_module_details": [
                            {"module": "app", "module_dir": "."},
                        ],
                    },
                },
            }

            restored = run_step._apply_pinned_source_snapshot(context, project)

        self.assertIsNotNone(restored)
        self.assertEqual(restored["tool"], "maven")
        self.assertEqual(
            restored["source_dirs"],
            [str(project.resolve() / "src/main/java")],
        )
        self.assertEqual(
            restored["project_scope"]["system_source"], str(project.resolve()),
        )
        self.assertRegex(restored["project_scope"]["scope_hash"], r"^[0-9a-f]{64}$")

    def test_rebuild_pinned_context_discovers_target_scope_in_detached_worktree(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            worktree = root / "worktree"
            source = worktree / "src" / "main" / "java"
            source.mkdir(parents=True)
            semantic_source = root / "src" / "main" / "java"
            semantic_source.mkdir(parents=True)
            context = {
                "current_resolved_commit": commit,
                "current_source_project_dir": str(root),
                "target_module": "app",
                "modules": ["app"],
                "active_maven_profiles": ["prod"],
                "input_origins": {},
                "source_dirs_status": "explicit",
                "source_dirs": [str(semantic_source)],
            }
            scope = {
                "schema": "java-upgrade-analyzer.project-scope.v1",
                "status": "complete",
                "target_module": "app",
                "system_source": str(worktree),
                "source_roots": [str(source)],
                "resource_roots": [],
                "missing_declared_roots": [],
                "candidate_module_details": [
                    {"module": "app", "module_dir": str(worktree)},
                ],
            }
            with patch.object(run_step, "_step1_ref_repository", return_value=root), patch.object(
                run_step, "_pinned_source_git_root", return_value=root,
            ), patch.object(
                run_step, "create_detached_worktree", return_value=worktree,
            ) as create, patch.object(run_step, "git_cmd", return_value=["git"]), patch.object(
                run_step, "detect_build_tool", return_value="maven",
            ), patch.object(run_step, "build_project_scope", return_value=scope) as build_scope, patch.object(
                run_step,
                "_resolve_source_dirs_plan",
                return_value={"source_dirs": [str(source)], "status": "detected"},
            ), patch.object(run_step, "remove_detached_worktree") as remove:
                rebuilt = run_step.rebuild_current_pinned_source_context(context, root)

        self.assertEqual(rebuilt["pinned_source_snapshot"]["commit"], commit)
        self.assertEqual(rebuilt["source_dirs"], [str(root / "src/main/java")])
        create.assert_called_once()
        build_scope.assert_called_once()
        remove.assert_called_once()

    def test_rebuild_pinned_context_lists_modules_when_target_is_unconfirmed(self):
        commit = "b" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            worktree = root / "worktree"
            source = worktree / "src" / "main" / "java"
            source.mkdir(parents=True)
            context = {
                "current_resolved_commit": commit,
                "current_source_project_dir": str(root),
                "target_module": "",
                "modules": [],
                "input_origins": {},
            }
            with patch.object(run_step, "_step1_ref_repository", return_value=root), patch.object(
                run_step, "_pinned_source_git_root", return_value=root,
            ), patch.object(run_step, "create_detached_worktree", return_value=worktree), patch.object(
                run_step, "git_cmd", return_value=["git"],
            ), patch.object(run_step, "detect_build_tool", return_value="gradle"), patch.object(
                run_step,
                "discover_project_modules",
                return_value={"modules": [{"module": "app", "module_dir": str(worktree)}]},
            ) as discover, patch.object(
                run_step,
                "_resolve_source_dirs_plan",
                return_value={"source_dirs": [str(source)], "status": "detected"},
            ), patch.object(run_step, "remove_detached_worktree"):
                rebuilt = run_step.rebuild_current_pinned_source_context(context, root)

        self.assertEqual(rebuilt["project_scope"]["status"], "insufficient")
        self.assertEqual(rebuilt["project_scope"]["candidate_modules"], ["app"])
        discover.assert_called_once()


class ApplicationSourceContractTest(unittest.TestCase):
    def test_application_source_materialization_distinguishes_remote_and_local(self):
        remote = {
            "repo_path": "/cache/repo",
            "git_endpoint": "https://example/repo.git",
            "resolved_commit": "a" * 40,
            "metadata_path": "/cache/meta.json",
        }
        with patch.object(run_step, "is_dependency_source_git_url", return_value=True), patch.object(
            run_step, "materialize_dependency_source_git_url", return_value=remote,
        ):
            result = run_step.materialize_application_source(
                "https://example/repo.git", ".", "report",
            )
        self.assertEqual(result["origin"], "user_git")
        self.assertEqual(result["resolved_commit"], "a" * 40)

        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary)
            with patch.object(run_step, "is_dependency_source_git_url", return_value=False), patch.object(
                run_step, "_git_repository_root", return_value=local,
            ), patch.object(run_step, "_git_repository_display", return_value="origin"):
                result = run_step.materialize_application_source(str(local), ".", "report")
            self.assertEqual(result["origin"], "user_path")
            self.assertEqual(result["git_root"], str(local))

        for invalid in ("", "/definitely/not/a/repository"):
            with self.subTest(invalid=invalid), self.assertRaises(run_step.StepError):
                run_step.materialize_application_source(invalid, ".", "report")

    def test_git_display_uses_canonical_remote_or_local_fallback(self):
        with patch.object(
            run_step, "run_cmd", return_value=("https://user:secret@example/repo.git\n", "", 0),
        ):
            display = run_step._git_repository_display(".")
        self.assertNotIn("secret", display)
        self.assertIn("example", display)
        with patch.object(run_step, "run_cmd", return_value=("", "", 1)):
            self.assertEqual(run_step._git_repository_display("."), str(Path(".").resolve()))

        self.assertTrue(run_step._is_redacted_git_display_url("https://***@example/repo"))
        self.assertTrue(run_step._is_redacted_git_display_url("https://x/repo?token=***"))
        self.assertTrue(run_step._is_sensitive_git_query_key("X-Amz-Signature"))
        self.assertFalse(run_step._is_sensitive_git_query_key("branch"))

    def test_git_endpoint_identity_and_persisted_transport_remove_all_credentials(self):
        raw = (
            "HTTPS://user:password@Example.COM/team/repo.git"
            "?branch=main&token=secret&X-Amz-Signature=signed#fragment"
        )
        canonical = run_step._canonical_git_endpoint(raw)
        persisted = run_step._persistable_git_transport_url(raw)

        for value in (canonical, persisted):
            self.assertNotIn("password", value)
            self.assertNotIn("secret", value)
            self.assertNotIn("Signature", value)
            self.assertIn("branch=main", value)
        self.assertEqual(canonical, "https://example.com/team/repo.git?branch=main")

    def test_application_source_detection_delegates_display_sanitization(self):
        with patch.object(run_step, "_git_repository_root", return_value=Path("/repo")), patch.object(
            run_step, "_git_repository_display", return_value="https://example/repo.git",
        ) as display:
            result = run_step.detect_application_source("/repo/subdir")

        self.assertEqual(result["display"], "https://example/repo.git")
        display.assert_called_once_with(Path("/repo"))

    def test_dependency_source_origin_failure_is_redacted_and_bounded(self):
        with patch.object(run_step, "git_cmd", return_value=["git"]), patch.object(
            run_step,
            "run_cmd",
            return_value=("", "https://user:secret@example/repo.git?token=hidden", 1),
        ) as command:
            success, detail = run_step._scrub_materialized_dependency_source_origin(
                "/repo",
                "https://user:secret@example/repo.git?branch=main&token=hidden",
            )

        self.assertFalse(success)
        self.assertNotIn("secret", detail)
        self.assertNotIn("hidden", detail)
        self.assertIn("***", detail)
        self.assertLessEqual(command.call_args.kwargs["timeout"], 10)


class DependencySourceContractTest(unittest.TestCase):
    def test_dependency_versions_ignore_unresolved_and_empty_pairs(self):
        rows = [
            {"coord": "g:a", "old_version": "1", "new_version": "2", "resolution_status": "resolved"},
            {"coord": "g:b", "old_version": "-", "new_version": "-", "resolution_status": "resolved"},
            {"coord": "g:c", "old_version": "1", "new_version": "2", "resolution_status": "unresolved"},
            {"coord": "", "old_version": "1", "new_version": "2"},
        ]
        with patch.object(run_step, "read_csv_rows", return_value=rows):
            self.assertEqual(
                run_step._dependency_change_versions("report"),
                {"g:a": {"base": "1", "current": "2"}},
            )

    def test_dependency_repository_plan_groups_sources_by_coordinate_and_repo(self):
        plan = {"candidates": [
            {"coord": "g:a", "repo_path": "/repo", "source_dir": "/repo/src"},
            {"coord": "g:a", "repo_path": "/repo", "module_root": "/repo/module"},
            {"coord": "", "repo_path": "/ignored"},
        ]}
        with patch.object(run_step, "_dependency_change_versions", return_value={"g:a": {}}), patch.object(
            run_step, "_build_dependency_source_plan", return_value=plan,
        ):
            observed_plan, grouped = run_step._dependency_repo_mapping_candidates(
                {"dependency_source_dirs": ["/repo"]}, "report",
            )
        self.assertIs(observed_plan, plan)
        self.assertEqual(grouped["g:a"]["/repo"]["source_dirs"], ["/repo/src"])
        self.assertEqual(grouped["g:a"]["/repo"]["module_roots"], ["/repo/module"])

        self.assertEqual(
            run_step._version_candidate_groups("/repo", "-"),
            {"status": "not_applicable", "candidates": []},
        )
        with patch.object(run_step, "match_remote_refs_by_version", return_value={"status": "matched"}) as match:
            self.assertEqual(run_step._version_candidate_groups("/repo", "1.0"), {"status": "matched"})
        match.assert_called_once_with("/repo", "1.0")

    def test_stale_dependency_cache_lock_is_reclaimed_only_after_owner_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            lock = cache / ".materialize.lock"
            lock.mkdir(parents=True)
            (lock / "owner.json").write_text(
                json.dumps({"pid": 424242}), encoding="utf-8",
            )
            with patch.object(run_step, "_pid_is_running", return_value=False) as alive:
                with run_step._dependency_source_cache_lock(cache, timeout=1):
                    self.assertTrue(lock.is_dir())
                    owner = json.loads((lock / "owner.json").read_text(encoding="utf-8"))
                    self.assertEqual(owner["pid"], os.getpid())
            self.assertFalse(lock.exists())
        alive.assert_called_once_with(424242)

    def test_dependency_inputs_distinguish_remote_materialization_from_local_resolution(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            local = project / "local dependency"
            local.mkdir(parents=True)
            remote = "https://example/team/dependency.git"
            materialized = {
                "git_url": "https://example/team/dependency.git",
                "repo_path": "/cache/dependency",
            }
            with patch.object(
                run_step,
                "is_dependency_source_git_url",
                side_effect=lambda value, *_args: str(value).startswith("https://"),
            ), patch.object(
                run_step,
                "materialize_dependency_source_git_url",
                return_value=materialized,
            ) as clone:
                result = run_step.materialize_dependency_source_inputs(
                    [remote, "local dependency"], project, Path(temporary) / "report",
                    clone_timeout=7,
                )

        self.assertEqual(
            result["dependency_source_dirs"],
            ["/cache/dependency", str(local.resolve())],
        )
        self.assertEqual(result["dependency_source_git_urls"], [remote])
        clone.assert_called_once_with(remote, Path(temporary) / "report", clone_timeout=7)

    def test_source_dir_normalization_keeps_order_and_ignores_empty_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self.assertEqual(
                run_step.normalize_source_dirs([" src/main/java ", "", 1], project),
                [str((project / "src/main/java").resolve())],
            )

    def test_relevant_coordinates_fall_back_to_persisted_step2_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            context_path = run_step.step2_context_path(report)
            context_path.parent.mkdir(parents=True)
            context_path.write_text(
                json.dumps({
                    "changed_dependencies": [
                        {"coord": "g:a"}, {"coord": "g:a"}, {"coord": "g:b"},
                    ],
                }),
                encoding="utf-8",
            )
            with patch.object(run_step, "read_csv_rows", return_value=[]):
                self.assertEqual(
                    run_step._collect_relevant_dependency_coords(report),
                    ["g:a", "g:b"],
                )

    def test_pinned_dependency_workspace_discovers_roots_and_redacts_fetch_failure(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            worktree = root / "worktree"
            module = worktree / "module"
            source = module / "src" / "main" / "java"
            source.mkdir(parents=True)
            success = {
                "coord": "g:ok",
                "current_commit": commit,
                "current_version": "2",
                "repo_path": str(root),
                "module_roots": [str(root / "module")],
            }
            failed = {
                "coord": "g:failed",
                "current_commit": "b" * 40,
                "current_version": "2",
                "repo_path": str(root),
            }

            def materialize(_root, candidate, **_kwargs):
                if candidate["commit"] == commit:
                    return {"status": "remote_source_resolved"}
                return {
                    "status": "remote_fetch_failed",
                    "failure": {
                        "reason_code": "NETWORK",
                        "reason": "https://user:secret@example/repo.git?token=hidden",
                    },
                }

            context = {"dependency_source_ref_bindings": [success, failed]}
            with patch.object(run_step, "_git_repository_root", return_value=root), patch.object(
                run_step, "materialize_remote_source_candidate", side_effect=materialize,
            ), patch.object(run_step, "create_detached_worktree", return_value=worktree), patch.object(
                run_step,
                "_resolve_source_dirs_plan",
                return_value={"source_dirs": [str(source)]},
            ) as resolve, patch.object(run_step, "remove_detached_worktree"):
                with run_step.materialize_pinned_dependency_source_workspaces(
                    context, root / "report",
                ) as pinned:
                    observed = dict(pinned)

        self.assertEqual(observed["dependency_repo_mappings"], [f"g:ok={worktree}"])
        self.assertEqual(observed["dependency_source_mappings"], [f"g:ok={source}"])
        self.assertNotIn(
            "secret",
            json.dumps(observed["dependency_source_snapshot_failures"]),
        )
        self.assertNotIn(
            "hidden",
            json.dumps(observed["dependency_source_snapshot_failures"]),
        )
        resolve.assert_called_once_with(module)

    def test_dependency_source_candidate_discovery_covers_filtering_and_layout_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            java_module = root / "java-module"
            kotlin_module = root / "kotlin-module"
            empty_module = root / "empty-module"
            java_source = java_module / "src" / "main" / "java"
            kotlin_source = kotlin_module / "src" / "main" / "kotlin"
            java_source.mkdir(parents=True)
            kotlin_source.mkdir(parents=True)
            empty_module.mkdir()
            locations = [
                {},
                {"coord": ""},
                {
                    "coord": "g:a",
                    "module_dir": str(java_module),
                    "repo_root": str(root),
                },
                {
                    "coord": "g:a",
                    "module_dir": str(java_module),
                    "repo_root": str(root),
                },
                {"coord": "g:b", "module_dir": str(kotlin_module)},
                {"coord": "g:c", "module_dir": str(empty_module)},
                {"coord": "g:d"},
            ]
            with patch.object(
                run_step, "resolve_repo_input_path", return_value=str(root),
            ) as resolve, patch.object(
                run_step, "infer_maven_coord_locations", return_value=locations,
            ) as discover:
                candidates = run_step._discover_dependency_source_candidates(
                    [None, "", f" {root} "],
                    relevant_coords=[None, "", "invalid", "g:a:linux", "g:a:mac"],
                )

        self.assertEqual(
            [(item["coord"], item["source_dir"]) for item in candidates],
            [
                ("g:a:linux", str(java_source)),
                ("g:a:mac", str(java_source)),
                ("g:b", str(kotlin_source)),
                ("g:c", ""),
                ("g:d", ""),
            ],
        )
        self.assertEqual(candidates[-1]["repo_path"], str(root))
        resolve.assert_called_once_with(str(root))
        discover.assert_called_once_with(
            str(root),
            max_poms=120,
            max_depth=4,
            target_coords={"g:a"},
        )
        self.assertEqual(run_step._discover_dependency_source_candidates(None), [])

    def test_dependency_source_plan_covers_matching_ambiguity_and_unmatched_matrix(self):
        candidates = [
            {"coord": "", "repo_path": "/ignored", "source_dir": "/ignored/src"},
            {"coord": "g:filtered", "repo_path": "/filtered"},
            {"coord": "g:a", "repo_path": "/repo-a", "source_dir": "/repo-a/src"},
            {"coord": "g:a", "repo_path": "/repo-a", "source_dir": ""},
            {"coord": "g:b", "repo_path": "/repo-b1", "source_dir": "/repo-b1/src"},
            {"coord": "g:b", "repo_path": "/repo-b2", "source_dir": "/repo-b2/src"},
            {"coord": "g:c", "repo_path": "", "source_dir": "/source-only"},
        ]
        with patch.object(
            run_step, "_discover_dependency_source_candidates", return_value=candidates,
        ) as discover:
            plan = run_step._build_dependency_source_plan(
                ["/input"],
                relevant_coords=[None, "", "g:a", "g:a", "g:b", "g:c", "g:missing"],
            )

        self.assertEqual(plan["relevant_coords"], ["g:a", "g:b", "g:c", "g:missing"])
        self.assertEqual(plan["dependency_repo_mappings"], ["g:a=/repo-a"])
        self.assertEqual(plan["dependency_source_mappings"], ["g:a=/repo-a/src", "g:c=/source-only"])
        self.assertEqual(plan["ambiguous_coords"][0]["coord"], "g:b")
        self.assertEqual(plan["unmatched_relevant_coords"], ["g:missing"])
        discover.assert_called_once_with(["/input"], relevant_coords={"g:a", "g:b", "g:c", "g:missing"})

        with patch.object(
            run_step,
            "_discover_dependency_source_candidates",
            return_value=[
                {"coord": "", "repo_path": "/ignored"},
                {"coord": "g:z", "repo_path": "/repo-z", "source_dir": None},
                {"coord": "g:z", "repo_path": None, "source_dir": "/repo-z/src"},
            ],
        ):
            unfiltered = run_step._build_dependency_source_plan(None)
        self.assertEqual(unfiltered["relevant_coords"], [])
        self.assertEqual(unfiltered["dependency_repo_mappings"], ["g:z=/repo-z"])
        self.assertEqual(unfiltered["dependency_source_mappings"], ["g:z=/repo-z/src"])

    def test_dependency_source_git_probe_helpers_cover_deadline_and_result_matrix(self):
        commit40 = "a" * 40
        commit64 = "B" * 64
        with patch.object(run_step, "_dependency_source_remaining_timeout", return_value=0), patch.object(
            run_step, "run_cmd",
        ) as command:
            self.assertEqual(run_step._dependency_source_git_origin("/repo", deadline=1), "")
            self.assertEqual(run_step._dependency_source_git_head("/repo", deadline=1), "")
        command.assert_not_called()

        for result, expected in (
            (("https://example/repo.git\n", "", 0), "https://example/repo.git"),
            ((None, "", 0), ""),
            (("ignored", "", 1), ""),
        ):
            with self.subTest(origin_result=result), patch.object(
                run_step, "run_cmd", return_value=result,
            ):
                self.assertEqual(run_step._dependency_source_git_origin("/repo"), expected)

        for result, expected in (
            ((commit40.upper(), "", 0), commit40),
            ((commit64, "", 0), commit64.lower()),
            (("not-a-commit", "", 0), ""),
            ((commit40, "", 1), ""),
            ((None, "", 0), ""),
        ):
            with self.subTest(head_result=result), patch.object(
                run_step, "run_cmd", return_value=result,
            ):
                self.assertEqual(run_step._dependency_source_git_head("/repo"), expected)

        self.assertTrue(run_step._same_git_transport_url("https://x/repo/", "https://x/repo"))
        self.assertTrue(run_step._same_git_transport_url(None, ""))
        self.assertFalse(run_step._same_git_transport_url("https://x/a", None))
        self.assertFalse(run_step._same_git_transport_url(None, "https://x/b"))

    def test_materialized_dependency_repo_validation_covers_every_failure_stage(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.assertFalse(run_step._is_materialized_dependency_source_repo(repo / "missing", "https://x/repo"))

            with patch.object(Path, "is_dir", return_value=True), patch.object(
                Path, "is_symlink", return_value=True,
            ):
                self.assertFalse(run_step._is_materialized_dependency_source_repo(repo, "https://x/repo"))

            with patch.object(run_step, "_dependency_source_remaining_timeout", return_value=0), patch.object(
                run_step, "run_cmd",
            ) as command:
                self.assertFalse(run_step._is_materialized_dependency_source_repo(repo, "https://x/repo", deadline=1))
            command.assert_not_called()

            first_probe_cases = (("true", 1), ("false", 0), (None, 0))
            for stdout, rc in first_probe_cases:
                with self.subTest(first_probe=(stdout, rc)), patch.object(
                    run_step, "run_cmd", return_value=(stdout, "", rc),
                ):
                    self.assertFalse(run_step._is_materialized_dependency_source_repo(repo, "https://x/repo"))

            with patch.object(
                run_step, "_dependency_source_remaining_timeout", side_effect=[1, 0],
            ), patch.object(run_step, "run_cmd", return_value=("true", "", 0)):
                self.assertFalse(run_step._is_materialized_dependency_source_repo(repo, "https://x/repo", deadline=1))

            for head_result in (("", "", 1), ("short", "", 0), (None, "", 0)):
                with self.subTest(head_result=head_result), patch.object(
                    run_step,
                    "run_cmd",
                    side_effect=[("true", "", 0), head_result],
                ):
                    self.assertFalse(run_step._is_materialized_dependency_source_repo(repo, "https://x/repo"))

            for origin, expected in (
                ("https://x/repo/", True),
                ("https://x/other", False),
                ("", False),
            ):
                with self.subTest(origin=origin), patch.object(
                    run_step,
                    "run_cmd",
                    side_effect=[("true", "", 0), (commit, "", 0)],
                ), patch.object(
                    run_step, "_dependency_source_git_origin", return_value=origin,
                ):
                    self.assertEqual(
                        run_step._is_materialized_dependency_source_repo(repo, "https://x/repo"),
                        expected,
                    )

    def test_dependency_source_origin_scrub_covers_noop_deadline_and_failure_details(self):
        plain = "https://example/repo.git?branch=main"
        self.assertEqual(
            run_step._scrub_materialized_dependency_source_origin("/repo", plain),
            (True, ""),
        )
        self.assertEqual(
            run_step._scrub_materialized_dependency_source_origin("/repo", None),
            (True, ""),
        )
        secret = "https://user:password@example/repo.git?token=hidden"
        with patch.object(run_step, "_dependency_source_remaining_timeout", return_value=0), patch.object(
            run_step, "run_cmd",
        ) as command:
            success, reason = run_step._scrub_materialized_dependency_source_origin(
                "/repo", secret, deadline=1,
            )
        self.assertFalse(success)
        self.assertIn("deadline", reason)
        command.assert_not_called()

        results = (
            (("", "", 0), True, ""),
            (("", "stderr secret", 1), False, "stderr secret"),
            (("stdout secret", "", 1), False, "stdout secret"),
            (("", "", 7), False, "git config exited with 7"),
        )
        for command_result, expected_success, expected_text in results:
            with self.subTest(command_result=command_result), patch.object(
                run_step, "run_cmd", return_value=command_result,
            ):
                success, detail = run_step._scrub_materialized_dependency_source_origin(
                    "/repo", secret,
                )
            self.assertEqual(success, expected_success)
            if expected_text:
                self.assertIn(expected_text, detail)

    def test_dependency_source_cache_lock_covers_initialization_timeout_and_stale_owner_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            cache = root / "write-failure"
            cache.mkdir()
            with patch.object(run_step, "write_json", side_effect=OSError("disk")):
                with self.assertRaises(OSError):
                    with run_step._dependency_source_cache_lock(cache, timeout=None):
                        pass
            self.assertFalse((cache / ".materialize.lock").exists())

            cache = root / "live-owner"
            lock = cache / ".materialize.lock"
            lock.mkdir(parents=True)
            (lock / "owner.json").write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
            moments = iter((0.0, 0.0, 1.0, 1.0))
            with patch.object(run_step.time, "monotonic", side_effect=lambda: next(moments, 1.0)), patch.object(
                run_step.time, "sleep",
            ), patch.object(run_step, "_pid_is_running", return_value=True):
                with self.assertRaises(run_step.StepError) as raised:
                    with run_step._dependency_source_cache_lock(cache, timeout=0):
                        pass
            self.assertIn("DEPENDENCY_SOURCE_GIT_CACHE_LOCK_TIMEOUT", raised.exception.reason_codes)

            cache = root / "uninitialized-owner"
            lock = cache / ".materialize.lock"
            lock.mkdir(parents=True)
            (lock / "owner.json").write_text(json.dumps({"pid": "invalid"}), encoding="utf-8")
            old = time.time() - 10
            os.utime(lock, (old, old))
            with run_step._dependency_source_cache_lock(cache, timeout=1):
                owner = json.loads((lock / "owner.json").read_text(encoding="utf-8"))
                self.assertEqual(owner["pid"], os.getpid())
            self.assertFalse(lock.exists())

            cache = root / "stat-failure"
            lock = cache / ".materialize.lock"
            lock.mkdir(parents=True)
            (lock / "owner.json").write_text("{}", encoding="utf-8")
            moments = iter((0.0, 0.0, 1.0, 1.0))
            original_stat = Path.stat

            def fail_lock_stat(path, *args, **kwargs):
                if path == lock:
                    raise OSError("race")
                return original_stat(path, *args, **kwargs)

            with patch.object(run_step.time, "monotonic", side_effect=lambda: next(moments, 1.0)), patch.object(
                run_step.time, "sleep",
            ), patch.object(Path, "stat", fail_lock_stat):
                with self.assertRaises(run_step.StepError):
                    with run_step._dependency_source_cache_lock(cache, timeout=0):
                        pass

    def test_dependency_source_git_materialization_rejects_invalid_and_unsafe_cache_paths(self):
        for value in (None, "", "/local/not-a-git-url"):
            with self.subTest(value=value), self.assertRaises(run_step.StepError):
                run_step.materialize_dependency_source_git_url(value, "/report")

        endpoint = "https://example/repo.git"
        digest = run_step.hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            cache_root = runtime_root / "dependency_source_git"
            cache_entry = cache_root / digest[:24]

            def root_is_symlink(path):
                return path == cache_root

            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                Path, "is_symlink", root_is_symlink,
            ), self.assertRaises(run_step.StepError) as raised:
                run_step.materialize_dependency_source_git_url(endpoint, "/report")
            self.assertIn("DEPENDENCY_SOURCE_GIT_CACHE_PATH_UNSAFE", raised.exception.reason_codes)

            def entry_is_symlink(path):
                return path == cache_entry

            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                Path, "is_symlink", entry_is_symlink,
            ), self.assertRaises(run_step.StepError) as raised:
                run_step.materialize_dependency_source_git_url(endpoint, "/report")
            self.assertIn("DEPENDENCY_SOURCE_GIT_CACHE_PATH_UNSAFE", raised.exception.reason_codes)

    def test_dependency_source_git_materialization_covers_deadline_and_reuse_matrix(self):
        endpoint = "https://example/repo.git"
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
            ), patch.object(run_step.time, "monotonic", side_effect=[0.0, 0.0, 2.0]):
                with self.assertRaises(run_step.StepError) as raised:
                    run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=1)
            self.assertIn("DEPENDENCY_SOURCE_GIT_OPERATION_DEADLINE_EXCEEDED", raised.exception.reason_codes)

        for label, scrub, head, expected_code in (
            ("scrub-failed", (False, "denied"), commit, "DEPENDENCY_SOURCE_GIT_ORIGIN_SCRUB_FAILED"),
            ("head-missing", (True, ""), "", "DEPENDENCY_SOURCE_GIT_COMMIT_UNRESOLVED"),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                runtime_root = Path(temporary) / "runtime"
                with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                    run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
                ), patch.object(run_step.time, "monotonic", return_value=0.0), patch.object(
                    run_step, "_is_materialized_dependency_source_repo", return_value=True,
                ), patch.object(
                    run_step, "_scrub_materialized_dependency_source_origin", return_value=scrub,
                ), patch.object(run_step, "_dependency_source_git_head", return_value=head):
                    with self.assertRaises(run_step.StepError) as raised:
                        run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=5)
                self.assertIn(expected_code, raised.exception.reason_codes)

        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            digest = run_step.hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
            cache_entry = runtime_root / "dependency_source_git" / digest[:24]
            removable = cache_entry / "repository.clone-old"
            ignored_file = cache_entry / "repository.clone-file"
            removable.mkdir(parents=True)
            ignored_file.write_text("not a directory", encoding="utf-8")
            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
            ), patch.object(run_step.time, "monotonic", return_value=0.0), patch.object(
                run_step, "_is_materialized_dependency_source_repo", return_value=True,
            ), patch.object(
                run_step, "_scrub_materialized_dependency_source_origin", return_value=(True, ""),
            ), patch.object(run_step, "_dependency_source_git_head", return_value=commit):
                result = run_step.materialize_dependency_source_git_url(
                    endpoint, "/report", clone_timeout=5,
                )
            metadata = json.loads(Path(result["metadata_path"]).read_text(encoding="utf-8"))
            removable_exists = removable.exists()
            ignored_file_exists = ignored_file.exists()
        self.assertTrue(result["reused"])
        self.assertEqual(result["clone_attempts"], 0)
        self.assertEqual(metadata["status"], "ready")
        self.assertFalse(removable_exists)
        self.assertTrue(ignored_file_exists)

    def test_dependency_source_git_materialization_records_bounded_retry_evidence(self):
        raw_url = "https://user:password@example/repo.git?token=hidden"
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
            ), patch.object(run_step.time, "monotonic", return_value=0.0), patch.object(
                run_step.time, "sleep",
            ) as sleep, patch.object(
                run_step,
                "run_cmd",
                side_effect=[
                    ("", "timeout from credential URL", 1),
                    ("network stdout", "", 1),
                    ("", "", 7),
                ],
            ), patch.object(
                run_step,
                "classify_fetch_failure",
                side_effect=[("network_timeout", True), ("network", True), ("unknown", False)],
            ):
                with self.assertRaises(run_step.StepError) as raised:
                    run_step.materialize_dependency_source_git_url(raw_url, "/report", clone_timeout=10)
            metadata_paths = list(runtime_root.rglob("metadata.json"))
            self.assertEqual(len(metadata_paths), 1)
            metadata = json.loads(metadata_paths[0].read_text(encoding="utf-8"))

        serialized = json.dumps(metadata, ensure_ascii=False)
        self.assertEqual(metadata["status"], "clone_failed")
        self.assertEqual(len(metadata["attempts"]), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertNotIn("password", serialized)
        self.assertNotIn("hidden", serialized)
        self.assertIn("DEPENDENCY_SOURCE_GIT_CLONE_FAILED", raised.exception.reason_codes)

    def test_dependency_source_git_materialization_removes_invalid_clone_and_existing_cache(self):
        endpoint = "https://example/repo.git"
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            digest = run_step.hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
            repo_path = runtime_root / "dependency_source_git" / digest[:24] / "repository"
            repo_path.mkdir(parents=True)
            marker = repo_path / "old"
            marker.write_text("stale", encoding="utf-8")

            def invalid_clone(command, **_kwargs):
                Path(command[-1]).mkdir(parents=True)
                return "", "", 0

            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
            ), patch.object(run_step.time, "monotonic", return_value=0.0), patch.object(
                run_step, "_is_materialized_dependency_source_repo", return_value=False,
            ), patch.object(run_step, "run_cmd", side_effect=invalid_clone), patch.object(
                run_step, "classify_fetch_failure", return_value=("invalid_repository", False),
            ):
                with self.assertRaises(run_step.StepError):
                    run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=5)

            attempts = list((repo_path.parent).glob("repository.clone-*"))
            self.assertFalse(marker.exists())
            self.assertEqual(attempts, [])
            metadata = json.loads((repo_path.parent / "metadata.json").read_text(encoding="utf-8"))
        self.assertIn("validation failed", metadata["attempts"][0]["reason"])

    def test_dependency_source_git_materialization_covers_late_deadlines_and_symlink_matrix(self):
        endpoint = "https://example/repo.git"

        deadline_cases = (
            ("after-cache-validation", [0.0, 0.0, 0.0, 2.0]),
            ("at-clone-loop-entry", [0.0, 0.0, 0.0, 0.0, 2.0]),
        )
        for label, moments in deadline_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                runtime_root = Path(temporary) / "runtime"
                timeline = iter(moments)
                with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                    run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
                ), patch.object(
                    run_step.time,
                    "monotonic",
                    side_effect=lambda: next(timeline, moments[-1]),
                ), patch.object(
                    run_step, "_is_materialized_dependency_source_repo", return_value=False,
                ), patch.object(run_step, "run_cmd") as command:
                    with self.assertRaises(run_step.StepError) as raised:
                        run_step.materialize_dependency_source_git_url(
                            endpoint, "/report", clone_timeout=1,
                        )
                self.assertIn("DEPENDENCY_SOURCE_GIT_OPERATION_DEADLINE_EXCEEDED", raised.exception.reason_codes)
                command.assert_not_called()

        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            digest = run_step.hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
            repo_path = runtime_root / "dependency_source_git" / digest[:24] / "repository"
            original_exists = Path.exists
            original_is_symlink = Path.is_symlink

            def broken_link_exists(path):
                return False if path == repo_path else original_exists(path)

            def broken_link_is_symlink(path):
                return True if path == repo_path else original_is_symlink(path)

            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
            ), patch.object(run_step.time, "monotonic", return_value=0.0), patch.object(
                run_step, "_is_materialized_dependency_source_repo", return_value=False,
            ), patch.object(Path, "exists", broken_link_exists), patch.object(
                Path, "is_symlink", broken_link_is_symlink,
            ):
                with self.assertRaises(run_step.StepError):
                    run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=5)

        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            digest = run_step.hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
            cache_entry = runtime_root / "dependency_source_git" / digest[:24]
            orphan = cache_entry / "repository.clone-preserved-link"
            orphan.mkdir(parents=True)
            original_is_symlink = Path.is_symlink

            def orphan_is_symlink(path):
                return True if path == orphan else original_is_symlink(path)

            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
            ), patch.object(run_step.time, "monotonic", return_value=0.0), patch.object(
                Path, "is_symlink", orphan_is_symlink,
            ), patch.object(
                run_step, "_is_materialized_dependency_source_repo", return_value=True,
            ), patch.object(
                run_step, "_scrub_materialized_dependency_source_origin", return_value=(True, ""),
            ), patch.object(run_step, "_dependency_source_git_head", return_value="a" * 40):
                run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=5)
            self.assertTrue(orphan.exists())

        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            clone_path = None

            def invalid_symlink_clone(command, **_kwargs):
                nonlocal clone_path
                clone_path = Path(command[-1])
                clone_path.mkdir(parents=True)
                return "", "failure", 1

            original_is_symlink = Path.is_symlink

            def clone_is_symlink(path):
                return bool(clone_path is not None and path == clone_path) or original_is_symlink(path)

            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
            ), patch.object(run_step.time, "monotonic", return_value=0.0), patch.object(
                Path, "is_symlink", clone_is_symlink,
            ), patch.object(
                run_step, "_is_materialized_dependency_source_repo", return_value=False,
            ), patch.object(run_step, "run_cmd", side_effect=invalid_symlink_clone), patch.object(
                run_step, "classify_fetch_failure", return_value=("invalid", False),
            ):
                with self.assertRaises(run_step.StepError):
                    run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=5)
            self.assertIsNotNone(clone_path)
            self.assertTrue(clone_path.exists())

    def test_dependency_source_git_materialization_retry_stop_conditions_are_distinct(self):
        endpoint = "https://example/repo.git"
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
            ), patch.object(run_step.time, "monotonic", return_value=0.0), patch.object(
                run_step.time, "sleep",
            ) as sleep, patch.object(
                run_step, "run_cmd", return_value=("", "retry", 1),
            ) as command, patch.object(
                run_step, "classify_fetch_failure", return_value=("network", True),
            ):
                with self.assertRaises(run_step.StepError):
                    run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=5)
            self.assertEqual(command.call_count, 3)
            self.assertEqual(sleep.call_count, 2)

        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime"
            timeline = iter((0.0, 0.0, 0.0, 0.0, 0.0, 2.0))
            with patch.object(run_step, "runtime_cache_dir", return_value=runtime_root), patch.object(
                run_step, "_dependency_source_cache_lock", return_value=nullcontext(),
            ), patch.object(
                run_step.time, "monotonic", side_effect=lambda: next(timeline, 2.0),
            ), patch.object(
                run_step, "run_cmd", return_value=("", "retry", 1),
            ) as command, patch.object(
                run_step, "classify_fetch_failure", return_value=("network", True),
            ), patch.object(run_step.time, "sleep") as sleep:
                with self.assertRaises(run_step.StepError):
                    run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=1)
            self.assertEqual(command.call_count, 1)
            sleep.assert_not_called()

    def test_dependency_source_git_materialization_covers_success_and_commit_failure(self):
        endpoint = "https://example/repo.git"
        commit = "a" * 40

        def run_case(*, head, create_concurrent=False, concurrent_valid=True, scrub=(True, "")):
            temporary = tempfile.TemporaryDirectory()
            runtime_root = Path(temporary.name) / "runtime"

            def clone(command, **_kwargs):
                temp_repo = Path(command[-1])
                temp_repo.mkdir(parents=True)
                if create_concurrent:
                    temp_repo.parent.joinpath("repository").mkdir()
                return "", "", 0

            validation = [False, True]
            if create_concurrent:
                validation.append(concurrent_valid)
            stack = ExitStack()
            stack.enter_context(patch.object(run_step, "runtime_cache_dir", return_value=runtime_root))
            stack.enter_context(patch.object(run_step, "_dependency_source_cache_lock", return_value=nullcontext()))
            stack.enter_context(patch.object(run_step.time, "monotonic", return_value=0.0))
            stack.enter_context(patch.object(run_step, "run_cmd", side_effect=clone))
            stack.enter_context(patch.object(
                run_step, "_is_materialized_dependency_source_repo", side_effect=validation,
            ))
            stack.enter_context(patch.object(
                run_step, "_scrub_materialized_dependency_source_origin", return_value=scrub,
            ))
            stack.enter_context(patch.object(run_step, "_dependency_source_git_head", return_value=head))
            stack.enter_context(patch.object(
                run_step, "classify_fetch_failure", return_value=("non_retryable", False),
            ))
            return temporary, stack

        temporary, stack = run_case(head=commit)
        with temporary, stack:
            success = run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=5)
            self.assertTrue(Path(success["repo_path"]).is_dir())
        self.assertFalse(success["reused"])
        self.assertEqual(success["clone_attempts"], 1)

        temporary, stack = run_case(head=commit, create_concurrent=True, concurrent_valid=True)
        with temporary, stack:
            concurrent = run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=5)
        self.assertEqual(concurrent["resolved_commit"], commit)

        failure_cases = (
            ("concurrent-invalid", dict(head=commit, create_concurrent=True, concurrent_valid=False), None),
            ("scrub-failed", dict(head=commit, scrub=(False, "denied")), "DEPENDENCY_SOURCE_GIT_CLONE_FAILED"),
            ("head-missing", dict(head=""), "DEPENDENCY_SOURCE_GIT_COMMIT_UNRESOLVED"),
        )
        for label, options, reason_code in failure_cases:
            temporary, stack = run_case(**options)
            with self.subTest(label=label), temporary, stack:
                with self.assertRaises(run_step.StepError) as raised:
                    run_step.materialize_dependency_source_git_url(endpoint, "/report", clone_timeout=5)
            if reason_code:
                self.assertIn(reason_code, raised.exception.reason_codes)

    def test_dependency_source_inputs_cover_empty_entries_and_empty_collection(self):
        self.assertEqual(
            run_step.materialize_dependency_source_inputs(None, "/project", "/report"),
            {
                "dependency_source_dirs": [],
                "dependency_source_git_urls": [],
                "dependency_source_git_materializations": [],
            },
        )
        with patch.object(run_step, "is_dependency_source_git_url") as classify:
            result = run_step.materialize_dependency_source_inputs(
                [None, "", 0], "/project", "/report",
            )
        self.assertEqual(result["dependency_source_dirs"], [])
        classify.assert_not_called()

    def test_pinned_source_workspace_covers_subproject_empty_and_invalid_root_matrix(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree = root / "worktree"
            project = worktree / "subproject"
            project.mkdir(parents=True)
            base_snapshot = {
                "schema": run_step.PINNED_SOURCE_SNAPSHOT_SCHEMA,
                "commit": commit,
                "project_path": "subproject",
                "source_roots": [],
                "resource_roots": [],
            }
            context = {
                "current_resolved_commit": commit,
                "pinned_source_snapshot": base_snapshot,
            }
            with patch.object(run_step, "_pinned_snapshot_matches_context", return_value=True), patch.object(
                run_step, "_step1_ref_repository", return_value=root,
            ), patch.object(run_step, "_pinned_source_git_root", return_value=root), patch.object(
                run_step, "create_detached_worktree", return_value=worktree,
            ), patch.object(run_step, "remove_detached_worktree") as remove:
                with run_step.materialize_pinned_source_workspace(context, root) as materialized:
                    self.assertEqual(materialized["project_root"], project.resolve())
                    self.assertEqual(materialized["source_dirs"], [])
                    self.assertEqual(materialized["resource_dirs"], [])
            remove.assert_called_once()

            root_snapshot = {
                **base_snapshot,
                "source_roots": ["."],
                "resource_roots": ["."],
            }
            root_context = {
                "current_resolved_commit": commit,
                "pinned_source_snapshot": root_snapshot,
            }
            with patch.object(run_step, "_pinned_snapshot_matches_context", return_value=True), patch.object(
                run_step, "_step1_ref_repository", return_value=root,
            ), patch.object(run_step, "_pinned_source_git_root", return_value=root), patch.object(
                run_step, "create_detached_worktree", return_value=worktree,
            ), patch.object(run_step, "remove_detached_worktree"):
                with run_step.materialize_pinned_source_workspace(root_context, root) as materialized:
                    self.assertEqual(materialized["source_dirs"], [str(project.resolve())])
                    self.assertEqual(materialized["resource_dirs"], [str(project.resolve())])

            cases = (
                ("missing-project", {**base_snapshot, "project_path": "missing"}, "PINNED_SOURCE_PROJECT_MISSING_AT_COMMIT"),
                ("invalid-source", {**base_snapshot, "source_roots": ["../outside"]}, "PINNED_SOURCE_PATH_INVALID"),
                ("missing-source", {**base_snapshot, "source_roots": ["missing-src"]}, "PINNED_SOURCE_ROOT_MISSING_AT_COMMIT"),
                ("invalid-resource", {**base_snapshot, "resource_roots": ["/outside"]}, "PINNED_SOURCE_PATH_INVALID"),
                ("missing-resource", {**base_snapshot, "resource_roots": ["missing-resources"]}, "PINNED_SOURCE_ROOT_MISSING_AT_COMMIT"),
            )
            for label, snapshot, reason_code in cases:
                with self.subTest(label=label):
                    failing_context = {
                        "current_resolved_commit": commit,
                        "pinned_source_snapshot": snapshot,
                    }
                    with patch.object(run_step, "_pinned_snapshot_matches_context", return_value=True), patch.object(
                        run_step, "_step1_ref_repository", return_value=root,
                    ), patch.object(run_step, "_pinned_source_git_root", return_value=root), patch.object(
                        run_step, "create_detached_worktree", return_value=worktree,
                    ), patch.object(run_step, "remove_detached_worktree") as cleanup:
                        with self.assertRaises(run_step.StepError) as raised:
                            with run_step.materialize_pinned_source_workspace(failing_context, root):
                                pass
                    self.assertIn(reason_code, raised.exception.reason_codes)
                    cleanup.assert_called_once()

            with patch.object(run_step, "_pinned_snapshot_matches_context", return_value=True), patch.object(
                run_step, "_step1_ref_repository", return_value=root,
            ), patch.object(run_step, "_pinned_source_git_root", return_value=root), patch.object(
                run_step, "create_detached_worktree", side_effect=RuntimeError("create failed"),
            ), patch.object(run_step, "remove_detached_worktree") as cleanup:
                with self.assertRaises(RuntimeError):
                    with run_step.materialize_pinned_source_workspace(context, root):
                        pass
            cleanup.assert_not_called()

    def test_pinned_dependency_workspaces_cover_skip_revision_repository_and_root_failures(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            worktree = root / "worktree"
            worktree.mkdir()
            bindings = [
                None,
                {},
                {"coord": "skip", "current_commit": commit, "repo_path": str(root)},
                {"coord": "bad-revision", "current_commit": "branch", "current_version": "1"},
                {"coord": "missing-repo", "current_commit": commit, "repo_path": ""},
                {"coord": "fetch-failed", "current_commit": commit, "repo_path": str(root)},
                {"coord": "worktree-failed", "current_commit": "b" * 40, "repo_path": str(root)},
                {
                    "coord": "roots-missing",
                    "current_commit": commit,
                    "repo_path": str(root),
                    "source_dirs": [str(root / "outside")],
                    "module_roots": [str(root / "missing-module")],
                },
            ]
            context = {
                "dependency_source_ref_bindings": bindings,
                "skip_dependency_source_coords": ["skip"],
                "dependency_source_clone_timeout": 9,
            }

            def repository(value):
                return None if not value else root

            def materialize(_root, candidate, **_kwargs):
                if candidate["commit"] == commit and candidate["ref"] == "fetch":
                    return {"status": "remote_fetch_failed", "failure": None}
                return {"status": "remote_source_resolved"}

            bindings[5]["current_ref"] = "fetch"
            calls = {"create": 0}

            def create(*_args, **_kwargs):
                calls["create"] += 1
                if calls["create"] == 2:
                    raise RuntimeError("credential secret")
                return worktree

            with patch.object(run_step, "_git_repository_root", side_effect=repository), patch.object(
                run_step, "materialize_remote_source_candidate", side_effect=materialize,
            ), patch.object(run_step, "create_detached_worktree", side_effect=create), patch.object(
                run_step, "remove_detached_worktree",
            ) as cleanup, patch.object(run_step, "write_json") as write:
                with run_step.materialize_pinned_dependency_source_workspaces(context, root / "report") as observed:
                    statuses = {
                        item["coord"]: item["status"]
                        for item in observed["dependency_source_snapshot_failures"]
                    }

        self.assertEqual(statuses["bad-revision"], "current_revision_unavailable")
        self.assertEqual(statuses["missing-repo"], "dependency_source_repository_unavailable")
        self.assertEqual(statuses["fetch-failed"], "remote_fetch_failed")
        self.assertEqual(statuses["worktree-failed"], "dependency_source_worktree_failed")
        self.assertEqual(statuses["roots-missing"], "dependency_source_roots_missing_at_commit")
        self.assertEqual(observed["dependency_repo_mappings"], [])
        self.assertEqual(observed["dependency_source_mappings"], [])
        write.assert_called_once()
        cleanup.assert_called_once()

    def test_pinned_dependency_workspace_normalizes_malformed_state_without_generic_crashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = {
                "dependency_source_ref_bindings": ["malformed", 7, None, {}, {"coord": ""}],
                "skip_dependency_source_coords": {"unsupported": True},
            }
            with patch.object(run_step, "write_json"):
                with run_step.materialize_pinned_dependency_source_workspaces(
                    context, root / "report",
                ) as observed:
                    failures = observed["dependency_source_snapshot_failures"]
        self.assertEqual(
            [item["status"] for item in failures],
            ["dependency_source_ref_binding_invalid", "dependency_source_ref_binding_invalid"],
        )
        self.assertEqual([item["binding_index"] for item in failures], [0, 1])

        empty_contexts = (
            None,
            {
                "dependency_source_ref_bindings": [],
                "skip_dependency_source_coords": [None, "", "unused"],
                "dependency_source_clone_timeout": None,
            },
            {"dependency_source_clone_timeout": ""},
        )
        for context in empty_contexts:
            with self.subTest(context=context), tempfile.TemporaryDirectory() as temporary, patch.object(
                run_step, "write_json",
            ):
                with run_step.materialize_pinned_dependency_source_workspaces(
                    context, Path(temporary) / "report",
                ) as observed:
                    self.assertEqual(observed["dependency_source_snapshots"], [])

        for invalid_timeout in (True, 0, -1, "invalid"):
            with self.subTest(invalid_timeout=invalid_timeout), self.assertRaises(run_step.StepError):
                with run_step.materialize_pinned_dependency_source_workspaces(
                    {"dependency_source_clone_timeout": invalid_timeout}, "/report",
                ):
                    pass

    def test_pinned_dependency_workspace_reuses_one_commit_and_keeps_exact_skip_semantics(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "src" / "main" / "java"
            source.mkdir(parents=True)
            worktree = root / "worktree"
            mapped_source = worktree / "src" / "main" / "java"
            mapped_source.mkdir(parents=True)
            bindings = [
                {
                    "coord": "g",
                    "current_commit": commit.upper(),
                    "repo_path": str(root),
                    "source_dirs": [str(source)],
                    "current_ref": "refs/tags/v1",
                    "current_remote": "origin",
                    "current_canonical_ref": "refs/tags/v1",
                },
                {
                    "coord": "g:second",
                    "current_commit": commit,
                    "repo_path": str(root),
                    "source_dirs": [str(source)],
                    "current_version": "2",
                },
                {
                    "coord": "g:skip",
                    "current_commit": commit,
                    "repo_path": str(root),
                    "source_dirs": [str(source)],
                },
            ]
            context = {
                "dependency_source_ref_bindings": bindings,
                "skip_dependency_source_coords": "g:skip",
            }
            with patch.object(run_step, "_git_repository_root", return_value=root), patch.object(
                run_step,
                "materialize_remote_source_candidate",
                return_value={"status": "remote_source_resolved"},
            ), patch.object(
                run_step, "create_detached_worktree", return_value=worktree,
            ) as create, patch.object(run_step, "remove_detached_worktree") as cleanup, patch.object(
                run_step, "write_json",
            ):
                with run_step.materialize_pinned_dependency_source_workspaces(
                    context, root / "report",
                ) as observed:
                    snapshots = list(observed["dependency_source_snapshots"])

        self.assertEqual([item["coord"] for item in snapshots], ["g", "g:second"])
        self.assertEqual(snapshots[0]["commit"], commit)
        self.assertEqual(snapshots[0]["ref"], "refs/tags/v1")
        self.assertEqual(snapshots[0]["version"], "")
        self.assertEqual(snapshots[1]["version"], "2")
        self.assertEqual(create.call_count, 1)
        cleanup.assert_called_once()
        self.assertEqual(len(observed["dependency_repo_mappings"]), 2)
        self.assertEqual(len(observed["dependency_source_mappings"]), 2)

    def test_pinned_dependency_workspace_rejects_invalid_materializer_payloads_and_escaped_roots(self):
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            module = root / "module"
            module.mkdir()
            worktree = root / "worktree"
            (worktree / "module").mkdir(parents=True)
            outside = root / "outside"
            outside.mkdir()
            bindings = [
                {"coord": "invalid-result", "current_commit": commit, "repo_path": str(root)},
                {"coord": "invalid-failure", "current_commit": "b" * 40, "repo_path": str(root)},
                {
                    "coord": "escaped-root",
                    "current_commit": "c" * 40,
                    "repo_path": str(root),
                    "module_roots": [str(module)],
                },
                {
                    "coord": "empty-plan",
                    "current_commit": "d" * 40,
                    "repo_path": str(root),
                    "module_roots": [str(module)],
                },
                {
                    "coord": "missing-revision",
                    "current_commit": None,
                    "current_status": "missing",
                    "repo_path": str(root),
                },
                {
                    "coord": "no-roots",
                    "current_commit": "e" * 40,
                    "repo_path": str(root),
                },
                {
                    "coord": "non-dir-plan",
                    "current_commit": "f" * 40,
                    "repo_path": str(root),
                    "module_roots": [str(module)],
                },
            ]

            def materialize(_root, candidate, **_kwargs):
                if candidate["commit"] == commit:
                    return None
                if candidate["commit"] == "b" * 40:
                    return {"status": "", "failure": "malformed"}
                return {"status": "remote_source_resolved"}

            def source_plan(_module):
                current = source_plan.calls
                source_plan.calls += 1
                if current == 0:
                    return {"source_dirs": [str(outside)]}
                if current == 1:
                    return {"source_dirs": []}
                return {"source_dirs": [str(worktree / "missing-src")]}

            source_plan.calls = 0
            with patch.object(run_step, "_git_repository_root", return_value=root), patch.object(
                run_step, "materialize_remote_source_candidate", side_effect=materialize,
            ), patch.object(run_step, "create_detached_worktree", return_value=worktree), patch.object(
                run_step, "_resolve_source_dirs_plan", side_effect=source_plan,
            ), patch.object(run_step, "remove_detached_worktree"), patch.object(
                run_step, "write_json",
            ):
                with run_step.materialize_pinned_dependency_source_workspaces(
                    {"dependency_source_ref_bindings": bindings}, root / "report",
                ) as observed:
                    failures = {
                        item.get("coord"): item
                        for item in observed["dependency_source_snapshot_failures"]
                    }

        self.assertEqual(failures["invalid-result"]["status"], "dependency_source_materialization_invalid")
        self.assertEqual(failures["invalid-failure"]["status"], "remote_fetch_failed")
        self.assertEqual(failures["escaped-root"]["status"], "dependency_source_roots_missing_at_commit")
        self.assertEqual(failures["empty-plan"]["status"], "dependency_source_roots_missing_at_commit")
        self.assertEqual(failures["missing-revision"]["status"], "current_revision_unavailable")
        self.assertEqual(failures["missing-revision"]["version"], "")
        self.assertEqual(failures["missing-revision"]["match_status"], "missing")
        self.assertEqual(failures["no-roots"]["status"], "dependency_source_roots_missing_at_commit")
        self.assertEqual(failures["non-dir-plan"]["status"], "dependency_source_roots_missing_at_commit")
        self.assertEqual(observed["dependency_source_mappings"], [])


class UserInteractionContractTest(unittest.TestCase):
    def test_user_field_rendering_and_default_actions_are_deterministic(self):
        self.assertEqual(run_step._user_field_label("target_module"), "目标模块")
        self.assertEqual(run_step._user_field_label("custom"), "custom")
        self.assertEqual(
            run_step._user_field_description("target_module"), "要分析的业务模块。",
        )
        self.assertEqual(
            run_step._user_field_description("custom", {"description": "自定义说明"}),
            "自定义说明",
        )
        self.assertEqual(
            run_step._format_user_field("target_module"),
            "目标模块：要分析的业务模块。",
        )
        self.assertEqual(run_step._format_user_field("custom"), "custom")

        self.assertEqual(
            run_step.default_interaction_action({"options": [{"id": "retry"}, {"id": "continue"}]}),
            "continue",
        )
        self.assertEqual(
            run_step.default_interaction_action({"options": [{"id": "retry"}]}),
            "retry",
        )
        self.assertEqual(run_step.default_interaction_action({}), "continue")

    def test_resume_resolution_enforces_current_decision_card(self):
        pending = {"step_id": "step3", "kind": "input_request"}
        self.assertEqual(run_step.resolve_resume_step_id("step4", pending, "continue"), "step3")
        self.assertEqual(run_step.resolve_resume_step_id("step4", pending, "rerun_current_step"), "step3")
        self.assertEqual(run_step.resolve_resume_step_id("step4", pending, "ignore"), "step4")
        with self.assertRaises(run_step.StepError):
            run_step.resolve_resume_step_id("step4", pending, "restart_from_step", {})
        with patch.object(run_step, "allowed_restart_step_ids", return_value=["step1", "step2"]):
            self.assertEqual(
                run_step.resolve_resume_step_id(
                    "step4", pending, "restart_from_step", {"restart_step_id": "step1"},
                ),
                "step1",
            )
            with self.assertRaises(run_step.StepError):
                run_step.resolve_resume_step_id(
                    "step4", pending, "restart_from_step", {"restart_step_id": "step5"},
                )

    def test_partial_scope_notes_recognize_language_and_coordinate_evidence(self):
        resolution = {"options": [{"coord": "g:a"}]}
        self.assertTrue(run_step._notes_look_like_partial_scope("只分析核心模块", resolution))
        self.assertTrue(run_step._notes_look_like_partial_scope("select G:A", resolution))
        self.assertFalse(run_step._notes_look_like_partial_scope("全量", resolution))
        self.assertFalse(run_step._notes_look_like_partial_scope("", resolution))

    def test_interaction_error_persistence_updates_every_recovery_artifact(self):
        state = {"state": {"completed_step": "step1"}, "step2": {"input": {"x": 1}}}
        interaction = {"status": "awaiting_user", "question": "需要输入"}
        enhanced = dict(interaction, status="awaiting_user_input")
        with patch.object(run_step, "previous_step_output", return_value={}), patch.object(
            run_step, "apply_interaction_protocol_enhancements", return_value=enhanced,
        ), patch.object(run_step, "update_main_state_state") as update, patch.object(
            run_step, "save_main_state",
        ) as save_state, patch.object(run_step, "save_interaction_file") as save_interaction, patch.object(
            run_step, "write_resume_snapshot",
        ) as snapshot:
            result = run_step.persist_interaction_required_error(
                state, "step2", "/tmp/report", interaction,
            )
        self.assertEqual(result["question"], "需要输入")
        update.assert_called_once()
        save_state.assert_called_once()
        save_interaction.assert_called_once()
        snapshot.assert_called_once()

    def test_response_rendering_uses_labels_for_unknown_array_fields(self):
        self.assertEqual(
            run_step._response_example_value("custom_targets", {"type": "array"}),
            ["<custom_targets>"],
        )
        card = run_step.build_user_decision_card({
            "question": "补充信息",
            "missing_inputs": [{"field": "target_module", "reason": "缺失"}],
            "input_modes": [{"label": "源码", "required_fields": ["application_source"]}],
            "options": [{"id": "continue", "label": "继续"}],
        })
        self.assertIn("目标模块", "\n".join(card))
        self.assertIn("应用源码", "\n".join(card))

    def test_decision_card_confirmation_renders_complete_ref_choices(self):
        card = run_step.build_user_decision_card({
            "question": "确认 | 分支\n选择",
            "confirmation_table": {
                "columns": ["信息", "Base", "Current"],
                "rows": [
                    {"label": "模块", "base": "base|api", "current": "current\napi"},
                    None,
                ],
            },
            "source_ref_decision_items": [
                {
                    "side": "base",
                    "candidates": [
                        {
                            "ref": "origin/main",
                            "commit": "a" * 40,
                            "aliases": [{"ref": "main"}, {"ref": ""}],
                        },
                        {"ref": "", "commit": "", "aliases": []},
                    ],
                },
                {
                    "side": "current",
                    "candidates": [
                        {"ref": f"origin/release-{index}", "commit": str(index) * 40}
                        for index in range(1, 8)
                    ],
                },
                {"side": "current", "candidates": []},
            ],
        })

        rendered = "\n".join(card)
        self.assertIn("当前需要确认：确认 | 分支选择", rendered)
        self.assertIn("base\\|api", rendered)
        self.assertIn("current<br>api", rendered)
        self.assertIn("别名：main", rendered)
        self.assertIn("Base 方案 1", rendered)
        self.assertIn("Current 方案 6", rendered)
        self.assertNotIn("release-7", rendered)
        self.assertIn("回复“确认”", rendered)

        default_card = "\n".join(run_step.build_user_decision_card({
            "confirmation_table": {"rows": []},
        }))
        self.assertIn("请确认正式分析信息", default_card)
        self.assertIn("| 信息 | Base | Current |", default_card)

    def test_decision_card_renders_every_general_section_and_bound(self):
        selection_options = [
            {
                "coord": f"com.acme:dep-{index}",
                "name": f"dep-{index}",
                "impact_priority_rank": index,
                "business_exact_referenced_api_count": index,
                "business_candidate_referenced_api_count": index + 1,
                "business_reference_occurrence_count": index + 2,
                "api_count": index + 3,
                "dependency_source_status": (
                    "available" if index == 1
                    else "unavailable" if index == 2
                    else "not_applicable" if index == 3
                    else "unknown" if index == 4
                    else "custom"
                ),
                "recommendation_reason": "" if index == 1 else f"原因 {index}",
            }
            for index in range(1, 13)
        ]
        module_candidates = [
            {"module": "app", "coord": "com.acme:app", "packaging": "jar"},
            {"path": "lib", "coord": "", "packaging": ""},
            "plain-module",
            "",
            *({"name": f"module-{index}"} for index in range(5, 23)),
        ]
        interaction = {
            "status": "awaiting_user_input",
            "question": "请选择分析范围",
            "user_reason": "需要用户确认",
            "recommended_action": "优先全量分析",
            "missing_inputs": [
                {"field": "target_module", "reason": "缺少部署模块"},
                {"field": "", "label": "显式字段", "reason": ""},
            ],
            "fallback_inputs": [
                {"field": "dependency_source_dirs", "reason": "提升精度"},
                {"field": "", "label": "可选字段"},
            ],
            "input_modes": [
                {"label": "源码", "required_fields": ["application_source", ""]},
                {"id": "artifact_inputs", "required_fields": []},
            ],
            "module_candidates": module_candidates,
            "source_ref_decision_items": [
                {
                    "side": "base",
                    "status": "fetch_failed",
                    "requested_ref": "main",
                    "candidates": [],
                },
                {
                    "side": "current",
                    "status": "ambiguous",
                    "requested_ref": "release",
                    "candidates": [
                        {
                            "ref": "origin/release" if index == 1 else "",
                            "display_ref": f"release-{index}" if index != 1 else "",
                            "commit": "" if index == 2 else str(index) * 40,
                        }
                        for index in range(1, 8)
                    ],
                },
            ],
            "dependency_source_ambiguities": [{
                "coord": "com.acme:dep",
                "versions": {"base": "1.0", "current": "2.0"},
                "candidates": [{
                    "repo_path": "/repo/dep",
                    "base_ref": "v1",
                    "base_commit": "a" * 40,
                    "current_ref": "v2",
                    "current_commit": "b" * 40,
                    "selection_key": "dep-1",
                }],
            }],
            "selection_options": selection_options,
            "selection_resolution": {
                "options": selection_options,
                "source_file": "/report/changed_dependencies.md",
            },
            "recommended_selection_options": selection_options,
            "recommended_candidate_count": 12,
            "scope_preview": {},
            "options": [
                {"id": "continue", "label": "继续"},
                {"id": "retry", "label": "重试", "description": "重新执行"},
                {"id": "skip", "label": "跳过", "description": ""},
                {"id": "restart_from_step", "label": "从早期步骤重启", "description": "修正输入"},
            ],
            "files_to_review": [
                "/report/module_candidates.md",
                "/report/changed_dependencies.md",
                "/report/evidence.json",
            ],
            "checklist_lines": ["- 核对依赖", "", "确认状态"],
        }

        rendered = "\n".join(run_step.build_user_decision_card(interaction))
        for expected in (
            "为什么暂停：需要用户确认",
            "推荐动作：优先全量分析",
            "需要补充的信息",
            "可选补充信息",
            "可选输入方式",
            "检测到的目标模块候选",
            "其余 2 个候选未展开",
            "远端查询或 fetch 在受控重试后仍失败",
            "当前展示 6 / 7 个候选",
            "需要处理的依赖包源码歧义",
            "Top 10 影响复核优先项，展示 10 / 10 个",
            "其余 2 个候选未在卡片中展开",
            "完整依赖选择清单",
            "需要修正更早输入时",
            "复核提示",
            "你可以直接回复",
        ):
            self.assertIn(expected, rendered)
        self.assertNotIn("module-22", rendered)
        self.assertNotIn("release-7", rendered)
        self.assertNotIn("- 继续", rendered)

    def test_decision_card_covers_informational_and_selection_fallbacks(self):
        empty = "\n".join(run_step.build_user_decision_card(None))
        self.assertIn("当前需要确认：请确认当前结果，然后继续", empty)

        informational = "\n".join(run_step.build_user_decision_card({
            "status": "informational",
            "question": "",
            "reason": "",
            "module_candidates": ["single", ""],
            "files_to_review": ["/report/result.json"],
            "checklist_lines": ["- 已完成"],
        }))
        self.assertIn("阶段结果：请确认当前结果，然后继续", informational)
        self.assertIn("本卡仅用于标准化记录阶段结果", informational)
        self.assertIn("结果证据文件", informational)
        self.assertIn("结果摘要", informational)
        self.assertNotIn("你可以直接回复", informational)

        option = {
            "name": "dep",
            "api_count": "2",
            "business_exact_referenced_api_count": "1",
            "business_candidate_referenced_api_count": "0",
            "business_reference_occurrence_count": "3",
        }
        fallback = "\n".join(run_step.build_user_decision_card({
            "selection_options": [option],
            "selection_resolution": {"options": [option], "source_file": ""},
            "scope_preview": {
                "total_api_count": 2,
                "business_exact_referenced_api_count": 1,
                "business_candidate_referenced_api_count": 0,
            },
            "recommended_candidate_count": 0,
            "options": [{"id": "continue"}],
        }))
        self.assertIn("当前没有可展示的影响复核优先项", fallback)
        self.assertIn("覆盖全部 1 个变化依赖、2 个变化 API", fallback)
        self.assertNotIn("完整依赖选择清单：", fallback)

        sparse = "\n".join(run_step.build_user_decision_card({
            "reason": "后备原因",
            "input_modes": [{"required_fields": ["", "target_module"]}],
            "module_candidates": [{}],
            "source_ref_decision_items": [{
                "side": "",
                "status": "",
                "requested_ref": "",
                "candidates": [{}, {"display_ref": "fallback-ref"}],
            }],
            "dependency_source_ambiguities": [{
                "coord": "",
                "versions": {},
                "candidates": [{}],
            }, {"coord": "empty-candidates"}],
            "selection_options": [{
                "coord": "",
                "name": "",
                "dependency_source_status": "",
                "recommendation_reason": "",
            }],
            "recommended_selection_options": [{"name": "visible"}],
            "recommended_candidate_count": 10,
            "selection_resolution": {
                "options": [{"name": "visible"}],
                "source_file": "/report/from-resolution.md",
            },
            "files_to_review": [],
            "options": [{"id": "continue"}, {"id": "restart_from_step"}],
        }))
        self.assertIn("为什么暂停：后备原因", sparse)
        self.assertIn("方案 1：`-`（commit ?）", sparse)
        self.assertIn("其余 9 个优先项见 `/report/from-resolution.md`", sparse)

        no_visible_target = "\n".join(run_step.build_user_decision_card({
            "selection_options": [{}],
            "recommended_selection_options": [{}],
            "selection_resolution": {"options": [{}]},
        }))
        self.assertNotIn("直接回复依赖名称或完整坐标", no_visible_target)
        self.assertNotIn("完整依赖选择清单：", no_visible_target)

        no_resolution_or_candidate_file = "\n".join(
            run_step.build_user_decision_card({
                "module_candidates": [f"module-{index}" for index in range(21)],
                "selection_options": [{}],
                "recommended_selection_options": [{}],
                "recommended_candidate_count": 3,
            })
        )
        self.assertIn("其余 1 个候选未展开", no_resolution_or_candidate_file)
        self.assertNotIn("完整候选及部署线索见", no_resolution_or_candidate_file)
        self.assertNotIn("其余 2 个优先项见", no_resolution_or_candidate_file)

        ordinary_options = "\n".join(run_step.build_user_decision_card({
            "options": [
                {"id": "continue"},
                {"id": "", "label": "", "description": ""},
                {"id": "restart_from_step", "label": "", "description": ""},
            ],
            "files_to_review": ["/report/plain.json"],
            "checklist_lines": ["plain"],
        }))
        self.assertIn("你可以选择", ordinary_options)
        self.assertIn("继续", ordinary_options)
        self.assertIn("选择此处理方式", ordinary_options)
        self.assertIn("从指定任务重新分析", ordinary_options)

    def test_decision_card_reply_examples_cover_all_input_modes(self):
        source_refs = run_step._decision_card_reply_examples({
            "missing_inputs": [
                None,
                {"field": ""},
                {"field": "base_artifact_path"},
                {"field": "current_artifact_path"},
                {"field": "dependency_source_dirs"},
            ],
            "required_fields": ["", "action", "dependency_repo_mappings"],
            "action_requirements": {
                "continue": {
                    "required_fields": [None, "", "action", "dependency_source_dirs"]
                }
            },
            "source_ref_decision_items": [
                {"side": "base", "status": "ambiguous", "candidates": [{}]},
                {"side": "current", "status": "ambiguous", "candidates": [{}]},
                {"side": "current", "status": "fetch_failed", "candidates": []},
                {"side": "current", "status": "ambiguous", "candidates": []},
            ],
        }, [], [None, {"id": "restart_from_step"}])
        self.assertEqual(
            source_refs,
            [
                "基准侧选方案 1；当前侧选方案 1，确认后继续",
                "网络已恢复，重试 fetch",
                "将 com.example:demo-lib 映射到 /path/to/demo-lib 后继续",
                "目标模块是 app，升级前产物是 /path/base.jar，升级后产物是 /path/current.jar",
                "依赖源码目录是 /path/to/dependency-repo，补充后重跑",
            ],
        )

        selection = run_step._decision_card_reply_examples(
            {"response_schema": {"properties": {"base_branch": {}, "current_branch": {}}}},
            [{"coord": "g:a"}, {"name": "b"}, {}],
            [],
        )
        self.assertEqual(selection[:2], ["全量分析", "只分析 g:a 和 b"])
        self.assertIn("目标模块是 app，基准分支 main，当前分支 feature/upgrade", selection)

        continue_examples = run_step._decision_card_reply_examples(
            {
                "response_schema": {"properties": ["invalid"]},
                "missing_inputs": [{"field": "base_branch"}],
                "action_requirements": {},
            },
            [],
            [{"id": "continue"}, {"id": ""}],
        )
        self.assertEqual(continue_examples, ["继续", "基准分支 main，当前分支 feature/upgrade"])

        fetch_only = run_step._decision_card_reply_examples({
            "source_ref_decision_items": [{
                "side": "base", "status": "fetch_failed", "candidates": []
            }],
        }, [], [])
        self.assertEqual(fetch_only, ["网络已恢复，重试 fetch"])

        choice_only = run_step._decision_card_reply_examples({
            "source_ref_decision_items": [{
                "side": "base", "status": "ambiguous", "candidates": [{}]
            }],
        }, [], [])
        self.assertEqual(choice_only, ["基准侧选方案 1，确认后继续"])

        required_blocks_continue = run_step._decision_card_reply_examples(
            {"required_fields": ["target_module"]},
            [],
            [{"id": "continue"}],
        )
        self.assertEqual(required_blocks_continue, [])

    def test_branch_clear_removes_every_bound_ref_identity(self):
        state = {
            "base_branch": "main",
            "base_branch_explicit": True,
            "base_resolved_commit": "a" * 40,
            "base_ref_binding": {"stale": True},
            "current_branch": "feature",
        }
        cleared = run_step.apply_user_response_clears(state, ["base_branch"])
        self.assertNotIn("base_branch", cleared)
        self.assertNotIn("base_resolved_commit", cleared)
        self.assertNotIn("base_ref_binding", cleared)
        self.assertEqual(cleared["current_branch"], "feature")

    def test_ref_selection_binds_exact_decision_card_commit(self):
        commit = "a" * 40
        interaction = {
            "step_id": "step1",
            "source_ref_decision_items": [{
                "side": "current",
                "field": "current_branch",
                "source_project_dir": "/repo",
                "candidates": [{
                    "selection_key": "current-1",
                    "ref": "origin/release",
                    "canonical_ref": "refs/heads/release",
                    "remote": "origin",
                    "commit": commit,
                }],
            }],
        }
        response = run_step.expand_step1_ref_selections(
            interaction,
            {"source_ref_selections": {"side": "current", "selection_key": "current-1"}},
        )
        self.assertEqual(response["current_expected_commit"], commit)
        self.assertEqual(response["current_ref_binding"]["expected_commit"], commit)
        self.assertEqual(response["current_ref_binding"]["canonical_ref"], "refs/heads/release")

    def test_pending_restart_applies_response_clears_card_and_resets_downstream_state(self):
        pending = {
            "step_id": "step3",
            "kind": "decision",
            "options": [{"id": "restart_from_step", "label": "重跑"}],
        }
        main_state = {
            "state": {"pending_interaction": pending},
            **{step: {"input": {}, "derived": {}, "output": {}} for step in run_step.STEP_SEQUENCE},
        }
        args = SimpleNamespace(response_json="{}", response_file="")
        response = {"action": "restart_from_step", "restart_step_id": "step2"}
        with patch.object(run_step, "validate_pending_interaction_response"), patch.object(
            run_step, "allowed_restart_step_ids", return_value=["step2"],
        ), patch.object(
            run_step, "apply_user_response_to_main_state", return_value=(main_state, {"x": 1}),
        ) as apply_response, patch.object(run_step, "clear_interaction_file") as clear, patch.object(
            run_step, "reset_step_state_for_restart",
        ) as reset, patch.object(run_step, "save_main_state"):
            result = run_step.apply_structured_user_response_if_present(
                args, ".", "report", main_state, "step4", user_response=response,
            )

        self.assertEqual(result["step_id"], "step2")
        apply_response.assert_called_once()
        clear.assert_called_once_with("report")
        reset.assert_called_once()

    def test_pending_interaction_is_rendered_before_awaiting_exit(self):
        interaction = {"step_id": "step2", "question": "确认范围"}
        with patch.object(run_step, "print_interaction_to_streams") as render, patch.object(
            run_step.sys, "stderr", io.StringIO(),
        ):
            result = run_step.maybe_return_pending_interaction("report", interaction)
        self.assertEqual(result, run_step.EXIT_AWAITING_USER)
        render.assert_called_once_with(interaction, "report")

    def test_step4_partial_resume_reports_high_risk_selection_boundary(self):
        main_state = {
            "step4": {"input": {"step5_scope_mode": "partial", "step5_selected_coords": ["g:a"]}},
            "step5": {"input": {}},
        }
        rows = [
            {"coord": "g:a", "severity": "P1"},
            {"coord": "g:b", "change_type": "unchanged"},
        ]
        selection = {
            "matched_rows": [rows[0]],
            "available_target_count": 2,
            "matched_row_count": 1,
        }
        with patch.object(run_step, "save_main_state"), patch.object(
            run_step, "read_csv_rows", return_value=rows,
        ), patch.object(run_step, "build_step5_selection_summary", return_value=selection), patch.object(
            run_step.sys, "stderr", io.StringIO(),
        ):
            run_step.handle_step4_resume_followups(
                main_state, "report", "step4", "continue",
            )
        self.assertEqual(main_state["step5"]["input"]["step5_scope_mode"], "partial")


class PublicationAndCleanupContractTest(unittest.TestCase):
    def test_step0_confirmation_is_sanitized_before_publication(self):
        captured = {}
        context = {
            "analysis_mode": "artifact_inputs",
            "base_artifact_path": "/artifacts/base.jar",
            "current_artifact_path": "/artifacts/current.jar",
            "application_source": "https://user:secret@example/repo.git",
            "target_module": "app",
            "base_resolved_commit": "a" * 40,
            "current_resolved_commit": "b" * 40,
        }
        with patch.object(run_step, "write_json", side_effect=lambda path, payload: captured.update(payload)):
            payload = run_step.write_step0_confirmation_record("report", context)
        self.assertEqual(payload, captured)
        self.assertNotIn("secret", json.dumps(payload))
        self.assertEqual(payload["artifacts"]["base"]["user_filename"], "base.jar")

    def test_step3_cleanup_removes_only_step3_owned_sections(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            aggregate = run_step.evidence_static_scan_dir(report) / run_step.STEP3_RISK_CANDIDATES_FILE
            aggregate.parent.mkdir(parents=True)
            aggregate.write_text("stale", encoding="utf-8")
            dep_dir = run_step.step4_api_changes_dir(report) / run_step.PER_DEPENDENCY_DIRNAME / "g_a"
            dep_dir.mkdir(parents=True)
            hits = dep_dir / run_step.PER_DEPENDENCY_CANDIDATE_HITS_FILE
            hits.write_text("stale", encoding="utf-8")
            summary = dep_dir / run_step.PER_DEPENDENCY_SUMMARY_FILE
            summary.write_text(json.dumps({
                "step3": {"stale": True},
                "keep": 1,
                "artifacts": {"candidate_hits_csv": "x", "keep": "y"},
            }), encoding="utf-8")
            run_step.cleanup_step3_candidate_outputs(report)
            result = json.loads(summary.read_text(encoding="utf-8"))
        self.assertFalse(aggregate.exists())
        self.assertFalse(hits.exists())
        self.assertNotIn("step3", result)
        self.assertEqual(result["artifacts"], {"keep": "y"})

    def test_validated_report_population_overrides_legacy_scope_counts(self):
        findings = {
            "schema": "java-upgrade-analyzer.binary-findings.v2",
            "coverage": {"overall_status": "complete"},
            "analysis_scope": {
                "mode": "full",
                "validation_status": "valid",
                "total_api_count": 99,
                "analyzed_api_count": 99,
                "available_dependency_count": 88,
                "analyzed_dependency_count": 88,
            },
            "report_population": {
                "schema": "java-upgrade-analyzer.step6-report-population.v1",
                "apis": {
                    "total_count": 3, "completed_count": 3, "incomplete_count": 0,
                    "population_unconfirmed": False,
                },
                "dependencies": {
                    "total_count": 2, "completed_count": 2, "incomplete_count": 0,
                    "population_unconfirmed": False,
                },
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            path = run_step.s6_findings_path(report)
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(findings), encoding="utf-8")
            with patch.object(run_step, "report_uses_release_protocol", return_value=False):
                summary = run_step.build_final_completion_summary(report)
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["api_total_count"], 3)
        self.assertEqual(summary["dependency_total_count"], 2)

    def test_committed_step4_checkpoint_requires_all_identity_bindings(self):
        binding = {
            "result_generation_identity": "generation",
            "validation_run_identity": "validation",
            "validation_result_sha256": "sha",
            "activation_identity": "activation",
        }
        checkpoint = {
            "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
            "status": "independent_validation_passed_pending_activation",
            "result_generation_identity": "generation",
            "validation_run_identity": "validation",
            "activation_identity": "activation",
        }
        active = {
            "result_generation_identity": "generation",
            "validation_run_identity": "validation",
            "validation_result_sha256": "sha",
        }
        receipt = {"state": "committed", "binding": binding}
        with patch.object(run_step, "_read_step4_active_descriptor", return_value=active), patch.object(
            run_step, "_read_background_json", return_value={"result_generation_identity": "generation"},
        ), patch.object(run_step, "_cleanup_committed_step4_checkpoint") as cleanup:
            run_step._finalize_stale_committed_step4_checkpoint("report", checkpoint, receipt)
        cleanup.assert_called_once()

        with patch.object(run_step, "_read_step4_active_descriptor", return_value={}), patch.object(
            run_step, "_read_background_json", return_value={},
        ):
            with self.assertRaises(run_step.StepError):
                run_step._finalize_stale_committed_step4_checkpoint("report", checkpoint, receipt)

    def test_downstream_gate_receipt_must_match_name_and_boolean_policy(self):
        valid = {"gate_receipt": {"gate_name": "final", "strict_risk_gate": True}}
        with patch.object(run_step, "report_publication_committed_receipt", return_value=valid), patch.object(
            run_step, "_downstream_report_publication_destinations", return_value=[],
        ):
            self.assertTrue(run_step._downstream_gate_policy_is_current(
                "report", "step6", expected_gate_name="final", expected_strict_risk_gate=True,
            ))
            self.assertFalse(run_step._downstream_gate_policy_is_current(
                "report", "step6", expected_gate_name="other", expected_strict_risk_gate=True,
            ))

    def test_landing_reads_only_release_bound_step6_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            deliverable = report / "deliverables" / "report.md"
            deliverable.parent.mkdir(parents=True)
            deliverable.write_text("report", encoding="utf-8")
            release = {stage: {"status": "current"} for stage in ("step4", "step5", "step6")}
            bundle = {
                "findings": {"artifacts": {}},
                "deliverable_names": ["report.md"],
            }
            with patch.object(run_step, "report_uses_release_protocol", return_value=True), patch.object(
                run_step, "reconcile_current_release", return_value=release,
            ), patch.object(
                run_step, "load_consistent_step6_publication", return_value=bundle,
            ) as load:
                rows = run_step._landing_existing_artifact_rows(
                    report, {"state": {"completed_step": "step6"}},
                )
        self.assertIn(("依赖与 API 升级影响报告", "deliverables/report.md"), rows)
        load.assert_called_once_with(report)

    def test_legacy_landing_reads_findings_artifact_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            findings = run_step.s6_findings_path(report)
            findings.parent.mkdir(parents=True)
            findings.write_text(json.dumps({"artifacts": {"alerts_csv": True}}), encoding="utf-8")
            alerts = report / "evidence" / "call_chain" / "alerts.csv"
            alerts.parent.mkdir(parents=True)
            alerts.write_text("header\n", encoding="utf-8")
            with patch.object(run_step, "report_uses_release_protocol", return_value=False):
                rows = run_step._landing_existing_artifact_rows(report)
        self.assertIn(("原始分析记录", "evidence/call_chain/alerts.csv"), rows)

    def test_final_summary_uses_consistent_release_bundle_when_protocol_managed(self):
        findings = {
            "coverage": {"overall_status": "complete"},
            "analysis_scope": {"mode": "full", "validation_status": "valid"},
        }
        with patch.object(run_step, "report_uses_release_protocol", return_value=True), patch.object(
            run_step, "load_consistent_step6_publication", return_value={"findings": findings},
        ) as load:
            summary = run_step.build_final_completion_summary("report")
        self.assertEqual(summary["status"], "completed")
        load.assert_called_once_with("report")

    def test_activation_commit_uses_exact_pending_generation_and_token(self):
        generation = "a" * 64
        activation = "b" * 64
        result = {
            "result_generation_identity": generation,
            "activation_identity": activation,
        }
        with patch.object(run_step, "read_pending_binary_generation", return_value={"pending": True}), patch.object(
            run_step, "commit_pending_binary_generation", return_value=True,
        ) as commit:
            self.assertTrue(run_step._commit_binary_step4_activation_receipt("report", result))
        commit.assert_called_once()
        self.assertEqual(commit.call_args.kwargs["expected_current_identity"], generation)
        self.assertEqual(commit.call_args.kwargs["expected_activation_identity"], activation)

    def test_committed_report_transaction_is_never_rolled_back(self):
        transaction_id = "a" * 32
        binding = {"result_generation_identity": "g", "activation_identity": "a"}
        result = {
            **binding,
            "report_publication_transaction": {
                "transaction_id": transaction_id,
                "binding": binding,
            },
        }
        with patch.object(
            run_step,
            "report_publication_transaction_recovery_metadata",
            return_value={"state": "committed"},
        ), patch.object(
            run_step, "report_publication_transaction_receipt", return_value={"state": "committed"},
        ) as receipt, patch.object(run_step, "compare_and_restore_active_binary_generation") as restore:
            status = run_step._rollback_binary_step4_transaction("report", result)
        self.assertEqual(status["report_publication_rollback"], "already_committed")
        self.assertEqual(status["active_generation_rollback"], "not_attempted_after_report_commit")
        receipt.assert_called_once()
        restore.assert_not_called()

    def test_windows_compat_cleanup_can_durably_remove_regular_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary).resolve()
            target = report / "nested" / "checkpoint.json"
            target.parent.mkdir()
            target.write_text("{}", encoding="utf-8")
            with patch.object(run_step, "fsync_directory") as fsync:
                self.assertTrue(run_step._remove_step_output_windows_compat(
                    report, Path("nested/checkpoint.json"), synchronize_parent=True,
                ))
            fsync.assert_called_once_with(target.parent)

    def test_windows_dispatch_uses_compat_checkpoint_and_cleanup_primitives(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary).resolve()
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            relative_checkpoint = (
                Path(run_step.BINARY_OUTPUT_RELATIVE_PATH)
                / "binary_observability"
                / "validation_checkpoint.json"
            )
            windows_os = SimpleNamespace(name="nt", path=os.path)

            with patch.object(
                run_step, "_secure_step_output_cleanup_supported", return_value=False,
            ), patch.object(run_step, "os", windows_os), patch.object(
                run_step, "_read_private_step4_checkpoint", return_value=b'{"status":"ok"}',
            ) as read_private:
                self.assertEqual(
                    run_step._read_step4_validation_checkpoint(report),
                    {"status": "ok"},
                )
            read_private.assert_called_once_with(checkpoint)

            with patch.object(
                run_step, "_secure_step_output_cleanup_supported", return_value=False,
            ), patch.object(run_step, "os", windows_os), patch.object(
                run_step, "_remove_step_output_windows_compat", return_value=True,
            ) as remove_checkpoint:
                run_step._delete_step4_validation_checkpoint_durable(checkpoint)
            remove_checkpoint.assert_called_once_with(
                report, relative_checkpoint, synchronize_parent=True,
            )

            output = report / "runtime" / "state.json"
            with patch.object(
                run_step, "_secure_step_output_cleanup_supported", return_value=False,
            ), patch.object(run_step, "os", windows_os), patch.object(
                run_step, "_remove_step_output_windows_compat", return_value=True,
            ) as remove_output:
                self.assertTrue(
                    run_step._remove_step_output_without_following_parent_links(
                        report, output,
                    )
                )
            remove_output.assert_called_once_with(report, Path("runtime/state.json"))


class Step0AndSubprocessContractTest(unittest.TestCase):
    @staticmethod
    def _default_args(project, report):
        return SimpleNamespace(
            project_dir=str(project),
            report_dir=str(report),
            base_branch=None,
            current_branch=None,
            active_maven_profiles=None,
            dependency_source_dirs=[],
            dependency_source_clone_timeout=None,
            base_artifact_path="",
            current_artifact_path="",
            application_source="",
            base_jdk_home="",
            current_jdk_home="",
            binary_pipeline_config="",
            include_test_scope=False,
            strict_risk_gate=False,
            target_module="",
            base_tool="",
            current_tool="",
            manual_coord_overrides=[],
        )

    def test_revision_build_tool_detection_uses_pinned_tree_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            module = root / "module"
            module.mkdir()
            context = {
                "project_dir": str(module),
                "base_resolved_commit": "a" * 40,
            }
            with patch.object(run_step, "_step1_ref_repository", return_value=module), patch.object(
                run_step, "_git_repository_root", return_value=root,
            ), patch.object(run_step, "git_cmd", return_value=["git"]), patch.object(
                run_step, "run_cmd", return_value=("module/pom.xml\n", "", 0),
            ) as command:
                tool = run_step._detect_build_tool_for_revision(context, "base")

        self.assertEqual(tool, "maven")
        self.assertIn("ls-tree", command.call_args.args[0])

    def test_step0_jdk_detection_uses_artifact_and_manifest_oracles(self):
        artifact_context = {
            "base_artifact_path": "/base.jar",
            "current_artifact_path": "/current.jar",
        }
        with patch.object(
            run_step, "infer_step1_mode_fields", return_value={"analysis_mode": "artifact_inputs"},
        ), patch(
            "s2_context_from_deps.detect_jdk_from_artifact",
            side_effect=[
                {"status": "detected", "version": "8"},
                {"status": "detected", "version": "17"},
            ],
        ) as artifact_oracle:
            self.assertEqual(
                run_step._detect_step0_jdk_versions(artifact_context),
                {"base": "8", "current": "17"},
            )
        self.assertEqual(artifact_oracle.call_count, 2)

        checkout_context = {
            "project_dir": "/repo",
            "base_resolved_commit": "a" * 40,
            "current_resolved_commit": "b" * 40,
            "base_tool": "maven",
            "current_tool": "maven",
        }
        with patch.object(
            run_step, "infer_step1_mode_fields", return_value={"analysis_mode": "checkout_build"},
        ), patch.object(run_step, "_step1_ref_repository", return_value=Path("/repo")), patch(
            "s2_context_from_deps.detect_jdk_versions_from_manifests",
            side_effect=[("1.8", "1.8", {}), ("17.0.9", "17.0.9", {})],
        ) as manifest_oracle:
            self.assertEqual(
                run_step._detect_step0_jdk_versions(checkout_context),
                {"base": "8", "current": "17"},
            )
        self.assertEqual(manifest_oracle.call_count, 2)

    def test_explicit_binary_config_preflights_both_artifacts_policy_and_asm(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            base_artifact = root / "base.jar"
            current_artifact = root / "current.jar"
            asm = root / "asm.jar"
            for path in (base_artifact, current_artifact, asm):
                path.write_bytes(b"fixture")
            base_jdk = root / "jdk8"
            current_jdk = root / "jdk17"
            base_jdk.mkdir()
            current_jdk.mkdir()
            config_path = root / "pipeline.json"
            config_path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "base": {
                    "jdk_home": str(base_jdk),
                    "artifacts": [{"path": str(base_artifact), "loader_realm": "app", "slot": 0}],
                },
                "current": {
                    "jdk_home": str(current_jdk),
                    "artifacts": [{"path": str(current_artifact), "loader_realm": "app", "slot": 0}],
                },
                "asm_jar": str(asm),
                "tool_execution_policy": {"oracle_max_attempts": 3},
            }), encoding="utf-8")
            context = {
                "binary_pipeline_config": str(config_path),
                "base_jdk_home": str(base_jdk),
                "current_jdk_home": str(current_jdk),
            }

            def artifact_record(path, *, side):
                return {"path": str(path), "sha256": "f" * 64, "size_bytes": path.stat().st_size}

            with patch.object(
                run_step, "_preflight_artifact_input", side_effect=artifact_record,
            ) as preflight, patch.object(run_step, "resolve_asm_jar", return_value=asm.resolve()) as resolve:
                result, resolved_asm = run_step._preflight_explicit_binary_config(context, root)

        self.assertEqual(result["artifact_count"], 2)
        self.assertEqual(result["tool_execution_policy"]["oracle_max_attempts"], 3)
        self.assertEqual(resolved_asm, asm.resolve())
        self.assertEqual(preflight.call_count, 2)
        resolve.assert_called_once_with(asm.resolve())

    def test_gradle_preflight_preserves_failure_detail_and_always_removes_worktree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            worktree = root / "worktree"
            worktree.mkdir()
            jdk = root / "jdk"
            jdk.mkdir()
            context = {
                "base_resolved_commit": "a" * 40,
                "base_tool": "gradle",
                "base_jdk_home": str(jdk),
            }
            with patch.object(run_step, "_step1_ref_repository", return_value=root), patch.object(
                run_step, "_pinned_source_git_root", return_value=root,
            ), patch.object(run_step, "_relative_path_inside", return_value="."), patch.object(
                run_step, "create_detached_worktree", return_value=worktree,
            ), patch.object(run_step, "gradle_cmd", return_value=["gradle"]), patch.object(
                run_step, "run_cmd", return_value=("", "wrapper failed", 1),
            ), patch.object(run_step, "remove_detached_worktree") as remove:
                with self.assertRaises(run_step.StepError) as raised:
                    run_step._preflight_pinned_build_tool(context, root, "base")

        self.assertIn("STEP0_BUILD_TOOL_PREFLIGHT_FAILED", raised.exception.reason_codes)
        self.assertIn("wrapper failed", str(raised.exception))
        remove.assert_called_once()

    def test_gate_failure_enriches_reason_codes_from_step4_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            coverage = run_step.runtime_coverage_dir(report) / "s4_coverage.json"
            coverage.parent.mkdir(parents=True)
            coverage.write_text(json.dumps({
                "binary": {
                    "reason_codes": ["TOP_LEVEL_GAP"],
                    "runs": [{"reason_code": "RUN_GAP"}],
                },
            }), encoding="utf-8")
            with patch.object(
                run_step,
                "run_python",
                side_effect=run_step.StepError("gate failed", reason_codes=["BASE"]),
            ):
                with self.assertRaises(run_step.StepError) as raised:
                    run_step.run_gate("jar_compare", report, ".")

        self.assertEqual(raised.exception.reason_codes, ["BASE", "TOP_LEVEL_GAP", "RUN_GAP"])

    def test_nonbinary_subprocess_failure_loads_declared_structured_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            result_path = Path(temporary) / "result.json"
            result_path.write_text(json.dumps({"reason_code": "GATE_REASON"}), encoding="utf-8")
            with patch.object(run_step, "run_cmd", return_value=("", "failed", 2)), patch.object(
                run_step, "print_output",
            ):
                with self.assertRaises(run_step.StepError) as raised:
                    run_step.run_python(
                        "gate.py", ["--result-json", str(result_path)], ".",
                    )
        self.assertIn("GATE_REASON", raised.exception.reason_codes)

    def test_stale_subprocess_result_is_removed_and_parent_fsynced(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "result.json"
            path.parent.mkdir()
            path.write_text("stale", encoding="utf-8")
            with patch.object(run_step, "fsync_directory") as fsync:
                run_step._prepare_fresh_subprocess_result(path)
            self.assertFalse(path.exists())
            fsync.assert_called_once_with(path.parent)

    def test_report_candidate_heartbeat_is_observable_and_stops_after_prepare(self):
        def prepare(*_args, **_kwargs):
            time.sleep(0.02)
            return {"phase": "step4"}

        with patch.object(run_step, "_workflow_mutation_lock_is_held", return_value=True), patch.object(
            run_step, "_report_publication_prepare_capability", return_value=nullcontext(),
        ), patch.object(
            run_step, "prepare_step4_publication_candidate", side_effect=prepare,
        ), patch.object(run_step, "emit_progress") as progress, patch.dict(
            os.environ, {"JUA_HEARTBEAT_INTERVAL_SECONDS": "0.001"},
        ):
            result = (
                run_step._prepare_binary_report_publication_candidate_in_process(
                    phase="step4", report_dir="report", output_dir="candidate",
                    candidate_activation_identity="token",
                )
            )

        self.assertEqual(result, {"phase": "step4"})
        self.assertGreaterEqual(progress.call_count, 1)

    def test_step3_derived_snapshot_reads_persisted_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            context = run_step.step2_context_path(report)
            context.parent.mkdir(parents=True)
            context.write_text(
                json.dumps({"jdk_upgraded": True, "springboot_major_upgrade": False}),
                encoding="utf-8",
            )
            snapshot = run_step.build_step_derived_snapshot("step3", {}, report)
        self.assertEqual(snapshot, {"jdk_upgraded": True, "springboot_major_upgrade": False})

    def test_run_context_materializes_application_and_canonicalizes_remembered_git_urls(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            report = project / "report"
            args = self._default_args(project, report)
            args.application_source = "https://user:secret@example/app.git"
            args.dependency_source_clone_timeout = 9
            with patch.object(run_step, "detect_build_tool", return_value=""), patch.object(
                run_step,
                "materialize_application_source",
                return_value={
                    "display": "https://example/app.git",
                    "repo_path": str(project),
                    "origin": "user_git",
                },
            ) as materialize, patch.object(
                run_step,
                "materialize_dependency_source_inputs",
                return_value={
                    "dependency_source_dirs": [],
                    "dependency_source_git_urls": [],
                    "dependency_source_git_materializations": [],
                },
            ) as dependencies, patch.object(
                run_step, "_apply_pinned_source_snapshot", side_effect=lambda value, _root: value,
            ):
                context = run_step.build_run_context(
                    args,
                    {},
                    {
                        "dependency_source_git_urls": [
                            "https://user:token@example/dependency.git?branch=main&token=hidden",
                        ],
                    },
                )

        materialize.assert_called_once()
        dependencies.assert_called_once()
        self.assertEqual(dependencies.call_args.kwargs["clone_timeout"], 9)
        self.assertEqual(
            context["dependency_source_git_urls"],
            ["https://example/dependency.git?branch=main"],
        )

    def test_run_context_reuses_only_a_verified_remembered_application_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            remembered = project / "remembered"
            remembered.mkdir()
            args = self._default_args(project, project / "report")
            seed = {
                "application_source": "https://example/app.git",
                "application_source_display": "https://example/app.git",
                "application_source_repo_path": str(remembered),
            }
            with patch.object(run_step, "detect_build_tool", return_value=""), patch.object(
                run_step, "_git_repository_root", return_value=remembered,
            ) as git_root, patch.object(run_step, "materialize_application_source") as materialize, patch.object(
                run_step,
                "materialize_dependency_source_inputs",
                return_value={
                    "dependency_source_dirs": [],
                    "dependency_source_git_urls": [],
                    "dependency_source_git_materializations": [],
                },
            ), patch.object(
                run_step, "_apply_pinned_source_snapshot", side_effect=lambda value, _root: value,
            ):
                context = run_step.build_run_context(args, {}, seed)

        self.assertEqual(context["application_source_repo_path"], str(remembered))
        git_root.assert_called_once_with(remembered)
        materialize.assert_not_called()

    def test_step1_interaction_adds_identity_correction_fields(self):
        manifest = {
            "step1": {
                "title": "依赖识别",
                "outputs": [],
                "interaction": {
                    "type": "decision",
                    "question": "确认依赖身份",
                    "options": [{"id": "continue", "label": "继续"}],
                },
            },
        }
        payload = run_step.build_interaction_payload(
            "step1", Path("report"), manifest, Path("."), run_context={}, main_state={},
        )
        properties = payload["response_schema"]["properties"]
        self.assertIn("manual_coord_overrides", properties)
        self.assertIn("manual_artifact_identities", properties)


class Step4RecoveryContractTest(unittest.TestCase):
    def test_republication_marker_records_scope_refresh_from_pre_step4_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary).resolve()
            state = run_step.new_main_state(report)
            state["state"].update({
                "current_step": "step4",
                "completed_step": "step3",
                "pending_interaction": None,
            })
            state["step4"]["input"] = {"step0_confirmed": True}
            with patch.object(
                run_step,
                "_read_step4_active_descriptor",
                return_value={"result_generation_identity": "a" * 64},
            ), patch.object(run_step, "cleanup_step_outputs_from"), patch.object(
                run_step, "clear_interaction_file",
            ):
                marker = run_step._begin_step4_report_republication_state(
                    main_state=state, report_dir=report,
                )
        self.assertTrue(marker["refresh_scope_interaction"])
        self.assertEqual(state["state"]["current_step"], "step5")
        self.assertEqual(state["state"]["completed_step"], "step4")

    def test_republication_reconcile_persists_refreshed_scope_interaction(self):
        marker = {
            "schema": run_step._STEP4_REPORT_REPUBLICATION_MARKER_SCHEMA,
            "result_generation_identity": "a" * 64,
            "refresh_scope_interaction": True,
            "marker_identity": "ignored-by-patched-reader",
        }
        state = run_step.new_main_state("report")
        interaction = {
            "status": "awaiting_user_input",
            "question": "确认 Step5 范围",
            "kind": "decision",
        }
        with patch.object(run_step, "_step4_republication_marker", return_value=marker), patch.object(
            run_step, "build_restore_context", return_value={"step0_confirmed": True},
        ), patch.object(run_step, "build_interaction_payload", return_value=interaction), patch.object(
            run_step,
            "apply_interaction_protocol_enhancements",
            side_effect=lambda value, *_args, **_kwargs: dict(value, enhanced=True),
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "save_interaction_file",
        ) as save_interaction, patch.object(run_step, "write_resume_snapshot"):
            result = run_step._reconcile_main_state_after_step4_republication(
                main_state=state,
                report_dir="report",
                project_dir=".",
                manifest_steps={"step4": {}},
                verified_release={"binding": {"result_generation_identity": "a" * 64}},
            )

        self.assertTrue(result["enhanced"])
        self.assertEqual(state["state"]["status"], "awaiting_user_input")
        self.assertNotIn("step4_report_republication_pending", state["state"])
        save_interaction.assert_called_once()

    def test_current_republication_is_verified_and_earlier_restart_clears_marker(self):
        marker = {
            "result_generation_identity": "a" * 64,
            "refresh_scope_interaction": False,
        }
        state = run_step.new_main_state("report")
        state["step4"]["input"] = {"step0_confirmed": True}
        with patch.object(run_step, "_step4_republication_marker", return_value=marker), patch.object(
            run_step, "_workflow_has_reached_step4", return_value=True,
        ), patch.object(
            run_step,
            "verify_current_step4_release",
            return_value={"committed_receipt_identity": "receipt"},
        ) as verify, patch.object(
            run_step, "_reconcile_main_state_after_step4_republication", return_value=None,
        ):
            result = run_step._apply_step4_startup_recovery(
                decision={"action": run_step._STEP4_RELEASE_CURRENT},
                target_step_id="step6",
                args=SimpleNamespace(step="auto"),
                main_state=state,
                report_dir="report",
                project_dir=".",
                manifest_steps={"step4": {}},
                gate_name="jar_compare",
                strict_risk_gate=False,
                has_structured_response=False,
            )
        self.assertTrue(result["applied"])
        verify.assert_called_once()

        state["state"]["step4_report_republication_pending"] = marker
        with patch.object(run_step, "_step4_republication_marker", return_value=marker), patch.object(
            run_step, "_workflow_has_reached_step4", return_value=False,
        ), patch.object(run_step, "save_main_state"), patch.object(
            run_step, "_clear_step4_republication_marker", wraps=run_step._clear_step4_republication_marker,
        ) as clear:
            run_step._apply_step4_startup_recovery(
                decision={"action": run_step._STEP4_RELEASE_CURRENT},
                target_step_id="step2",
                args=SimpleNamespace(step="auto"),
                main_state=state,
                report_dir="report",
                project_dir=".",
                manifest_steps={"step4": {}},
                gate_name="jar_compare",
                strict_risk_gate=False,
                has_structured_response=False,
            )
        clear.assert_called_once_with(state)

    def test_startup_target_infers_nonpending_response_scope(self):
        target = run_step._startup_step4_recovery_target_hint(
            SimpleNamespace(step="auto"),
            {"state": {}},
            {"dependency_source_dirs": ["/repo"]},
        )
        self.assertEqual(target, "step0")

    def test_recovery_handles_legacy_irreversible_and_committed_transactions(self):
        transaction_id = "a" * 32
        binding = {
            "result_generation_identity": "b" * 64,
            "validation_run_identity": "c" * 64,
            "validation_result_sha256": "d" * 64,
            "activation_identity": "e" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary).resolve()
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            binary_root.mkdir(parents=True)
            legacy = {
                "state": "published",
                "implementation_status": "legacy",
                "transaction_id": transaction_id,
                "binding": binding,
            }
            with patch.object(run_step, "_read_step4_validation_checkpoint", return_value=None), patch.object(
                run_step, "read_pending_binary_generation", return_value={"pending": True},
            ), patch.object(
                run_step, "report_publication_transaction_recovery_metadata", return_value=legacy,
            ), patch.object(
                run_step, "_step4_activation_recovery_state", return_value="sealed_bound_generation",
            ), patch.object(
                run_step, "finalize_irreversible_report_publication",
            ) as finalize:
                disposition = run_step._recover_binary_step4_transaction(report)
            self.assertEqual(
                disposition,
                "committed_legacy_published_transaction_requires_republication",
            )
            finalize.assert_called_once()

            checkpoint = {
                "result_generation_identity": binding["result_generation_identity"],
                "validation_run_identity": binding["validation_run_identity"],
                "activation_identity": binding["activation_identity"],
            }
            committed = {
                "state": "committed",
                "implementation_status": "current",
                "transaction_id": transaction_id,
                "binding": binding,
            }
            with patch.object(run_step, "_read_step4_validation_checkpoint", return_value=checkpoint), patch.object(
                run_step, "read_pending_binary_generation", return_value=None,
            ), patch.object(
                run_step, "report_publication_transaction_recovery_metadata", return_value=committed,
            ), patch.object(
                run_step, "report_publication_transaction_receipt", return_value={"binding": binding},
            ), patch.object(
                run_step, "_finalize_stale_committed_step4_checkpoint",
            ) as stale, patch.object(run_step, "recover_report_publication") as recover:
                disposition = run_step._recover_binary_step4_transaction(report)
            self.assertEqual(disposition, "completed_committed_transaction")
            stale.assert_called_once()
            recover.assert_called_once()

    def test_gate_passed_recovery_finalizes_checkpoint_before_commit(self):
        transaction_id = "a" * 32
        binding = {
            "result_generation_identity": "b" * 64,
            "validation_run_identity": "c" * 64,
            "validation_result_sha256": "d" * 64,
            "activation_identity": "e" * 64,
        }
        checkpoint = {
            "result_generation_identity": binding["result_generation_identity"],
            "validation_run_identity": binding["validation_run_identity"],
            "activation_identity": binding["activation_identity"],
        }
        metadata = {
            "state": "gate_passed",
            "implementation_status": "current",
            "transaction_id": transaction_id,
            "binding": binding,
            "gate_receipt": {"gate_name": "jar_compare", "strict_risk_gate": False},
        }
        with patch.object(run_step, "_read_step4_validation_checkpoint", return_value=checkpoint), patch.object(
            run_step, "report_publication_transaction_recovery_metadata", return_value=metadata,
        ), patch.object(
            run_step, "_step4_activation_recovery_state", return_value="rollbackable",
        ), patch.object(run_step, "publish_report_publication"), patch.object(
            run_step, "_seal_binary_step4_activation",
        ), patch.object(run_step, "_finalize_binary_step4_transaction") as finalize, patch.object(
            run_step, "_commit_binary_step4_activation_receipt",
        ), patch.object(run_step, "commit_report_publication"):
            disposition = run_step._recover_binary_step4_transaction(
                "report",
                expected_gate_name="jar_compare",
                expected_strict_risk_gate=False,
            )
        self.assertEqual(disposition, "completed_gate_passed_transaction")
        self.assertEqual(finalize.call_count, 2)


class StepExecutionAndMainContractTest(unittest.TestCase):
    @staticmethod
    def _args(project, report):
        return SimpleNamespace(
            project_dir=str(project),
            report_dir=str(report),
            strict_risk_gate=False,
        )

    def _main_startup(self, state, manifest_steps=None):
        stack = ExitStack()
        stack.enter_context(patch.object(run_step, "load_seed_json_arg", return_value={}))
        stack.enter_context(patch.object(run_step, "load_main_state", return_value=state))
        stack.enter_context(patch.object(
            run_step, "recover_worktrees_before_execution", return_value={"removed_count": 0},
        ))
        stack.enter_context(patch.object(
            run_step,
            "load_manifest",
            return_value=({}, manifest_steps or {step: {"gate": "gate"} for step in run_step.STEP_SEQUENCE}),
        ))
        stack.enter_context(patch.object(
            run_step, "recover_downstream_report_publications", return_value={"actions": []},
        ))
        stack.enter_context(patch.object(run_step, "build_restore_context", return_value={}))
        stack.enter_context(patch.object(
            run_step,
            "_recover_and_apply_step4_startup_state",
            return_value={
                "applied": False,
                "discard_structured_response": False,
                "forced_step_id": "",
            },
        ))
        stack.enter_context(patch.object(
            run_step,
            "_apply_downstream_release_startup_state",
            return_value={
                "discard_structured_response": False,
                "forced_step_id": "",
                "release": {},
            },
        ))
        return stack

    def test_execute_step0_binds_preflight_jdks_and_confirmation_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            report = project / "report"
            args = self._args(project, report)
            context = {"step0_confirmation_acknowledged": True}
            preflight = {
                "sides": {
                    "base": {"jdk": {"java_major": "8"}},
                    "current": {"jdk": {"java_major": "17"}},
                },
            }
            with patch.object(run_step, "cleanup_step_outputs"), patch.object(
                run_step, "validate_step0_context",
            ) as validate, patch.object(
                run_step, "run_step0_preflight", return_value=preflight,
            ) as run_preflight, patch.object(
                run_step,
                "write_step0_confirmation_record",
                return_value={"confirmed_at": "now"},
            ) as write_record, patch.object(
                run_step, "build_run_context", side_effect=lambda _args, value, *_a, **_kw: dict(value),
            ), patch.object(run_step, "run_gate"), patch.object(
                run_step, "build_interaction_payload", return_value={"kind": "review"},
            ):
                interaction = run_step._execute_step_unlocked(
                    "step0", args, {"step0": {"gate": "preflight"}}, context,
                )

        self.assertEqual(context["jdk_base"], "8")
        self.assertEqual(context["jdk_current"], "17")
        self.assertTrue(context["step0_confirmed"])
        self.assertEqual(interaction, {"kind": "review"})
        validate.assert_called_once()
        run_preflight.assert_called_once()
        write_record.assert_called_once()

    def test_execute_step6_passes_fixed_findings_and_report_destinations(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            report = project / "report"
            args = self._args(project, report)
            context = {"strict_risk_gate": True}
            with patch.object(
                run_step,
                "_run_downstream_report_publication",
                return_value={"elapsed_seconds": 0.1},
            ) as publish, patch.object(
                run_step, "build_run_context", side_effect=lambda _args, value, *_a, **_kw: dict(value),
            ), patch.object(run_step, "build_interaction_payload", return_value=None):
                self.assertIsNone(run_step._execute_step_unlocked(
                    "step6", args, {"step6": {"gate": "binary_final_report"}}, context,
                ))

        self.assertEqual(publish.call_args.kwargs["output_findings"], run_step.s6_findings_path(report))
        self.assertEqual(publish.call_args.kwargs["output_report"], run_step.final_report_path(report))

    def test_main_describes_static_step0_contract_without_runtime_preconditions(self):
        stdout = io.StringIO()
        contract = {"schema": "contract"}
        with patch.object(run_step, "build_step0_static_contract", return_value=contract) as build, patch.object(
            run_step.sys, "stdout", stdout,
        ):
            result = run_step._main_with_workflow_lock_held(["--describe-step0-contract"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue()), contract)
        build.assert_called_once()

    def test_main_environment_failure_is_actionable_and_stops_before_state_load(self):
        environment = {
            "status": "failed",
            "checks": [{
                "component": "tool:git",
                "status": "failed",
                "observed": "missing",
                "expected": "available",
            }],
        }
        stderr = io.StringIO()
        with patch.object(run_step, "contract_payload", return_value=environment), patch.object(
            run_step.sys, "stderr", stderr,
        ), patch.object(run_step, "load_main_state") as load:
            result = run_step._main_with_workflow_lock_held(["--step", "auto"])
        self.assertEqual(result, 1)
        self.assertIn("命令行工具 git", stderr.getvalue())
        load.assert_not_called()

    def test_main_worktree_recovery_failure_reports_owned_diagnostic_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            report = project / "report"
            state = run_step.new_main_state(report)
            stderr = io.StringIO()
            with patch.object(run_step, "load_seed_json_arg", return_value={}), patch.object(
                run_step, "load_main_state", return_value=state,
            ), patch.object(
                run_step,
                "recover_worktrees_before_execution",
                side_effect=run_step.WorktreeRecoveryError("unsafe stale worktree"),
            ), patch.object(run_step.sys, "stderr", stderr):
                result = run_step._main_with_workflow_lock_held(
                    ["--step", "auto", "--project-dir", str(project), "--report-dir", str(report)],
                    _skip_environment_contract=True,
                )
        self.assertEqual(result, 1)
        self.assertIn(str(run_step.worktree_recovery_path(report)), stderr.getvalue())

    def test_main_refreshes_and_sanitizes_saved_pending_interaction(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            report = project / "report"
            state = run_step.new_main_state(report)
            state["state"].update({
                "current_step": "step1",
                "pending_interaction": {
                    "step_id": "step1",
                    "question": "确认 https://user:secret@example/repo.git",
                },
            })
            with self._main_startup(state), patch.object(
                run_step,
                "apply_interaction_protocol_enhancements",
                side_effect=lambda value, *_args, **_kwargs: dict(value, enhanced=True),
            ) as enhance, patch.object(run_step, "save_main_state"), patch.object(
                run_step, "save_interaction_file",
            ) as save_interaction, patch.object(run_step, "print_interaction_to_streams"), patch.object(
                run_step.sys, "stderr", io.StringIO(),
            ):
                result = run_step._main_with_workflow_lock_held(
                    ["--step", "auto", "--project-dir", str(project), "--report-dir", str(report)],
                    _skip_environment_contract=True,
                )

        self.assertEqual(result, run_step.EXIT_AWAITING_USER)
        self.assertTrue(state["state"]["pending_interaction"]["enhanced"])
        self.assertNotIn("secret", json.dumps(state["state"]["pending_interaction"]))
        enhance.assert_called_once()
        save_interaction.assert_called_once()

    def test_main_done_fast_path_requires_current_release_and_rechecks_integrity(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            report = project / "report"
            state = run_step.new_main_state(report)
            state["state"].update({
                "current_step": "done",
                "completed_step": "step6",
                "status": "completed",
            })
            summary = {"status": "completed", "limitations": []}
            with self._main_startup(state), patch.object(
                run_step, "require_current_release_stage",
            ) as require, patch.object(
                run_step, "detect_integrity_repair_step", return_value=None,
            ) as detect, patch.object(
                run_step, "build_final_completion_summary", return_value=summary,
            ) as build_summary, patch.object(run_step, "save_main_state"), patch.object(
                run_step, "write_report_landing_docs",
            ) as landing, patch.object(run_step.sys, "stderr", io.StringIO()):
                result = run_step._main_with_workflow_lock_held(
                    ["--step", "auto", "--project-dir", str(project), "--report-dir", str(report)],
                    _skip_environment_contract=True,
                )

        self.assertEqual(result, 0)
        require.assert_called_once_with(report, "step6", workflow_lock_held=True)
        detect.assert_called_once_with("step6", report)
        build_summary.assert_called_once_with(report)
        landing.assert_called_once_with(report, state)

    def test_main_step2_rebuilds_scope_when_current_commit_has_no_matching_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            report = project / "report"
            state = run_step.new_main_state(report)
            state["state"]["current_step"] = "step2"
            context = {"current_resolved_commit": "a" * 40, "step0_confirmed": True}
            rebuilt = dict(context, pinned_source_snapshot={"schema": "pinned"})
            with self._main_startup(state), patch.object(
                run_step, "prepare_main_state_for_step_execution", return_value="step2",
            ), patch.object(run_step, "build_step_input_context", return_value=context), patch.object(
                run_step, "build_run_context", return_value=context,
            ), patch.object(
                run_step, "rebuild_current_pinned_source_context", return_value=rebuilt,
            ) as rebuild, patch.object(run_step, "store_step_input"), patch.object(
                run_step, "save_main_state",
            ), patch.object(
                run_step, "execute_step", side_effect=run_step.StepError("stop after scope rebuild"),
            ), patch.object(run_step, "persist_step_error"), patch.object(
                run_step.sys, "stderr", io.StringIO(),
            ):
                result = run_step._main_with_workflow_lock_held(
                    ["--step", "step2", "--project-dir", str(project), "--report-dir", str(report)],
                    _skip_environment_contract=True,
                )

        self.assertEqual(result, 1)
        rebuild.assert_called_once_with(context, project)

    def test_main_persists_interaction_required_from_step_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary).resolve()
            report = project / "report"
            state = run_step.new_main_state(report)
            state["state"]["current_step"] = "step1"
            interaction = {"step_id": "step1", "question": "补充坐标"}
            with self._main_startup(state), patch.object(
                run_step, "prepare_main_state_for_step_execution", return_value="step1",
            ), patch.object(run_step, "build_step_input_context", return_value={}), patch.object(
                run_step, "build_run_context", return_value={"step0_confirmed": True},
            ), patch.object(run_step, "store_step_input"), patch.object(
                run_step, "save_main_state",
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=run_step.StepInteractionRequired(interaction),
            ), patch.object(
                run_step, "persist_interaction_required_error", return_value=interaction,
            ) as persist, patch.object(run_step, "print_interaction_to_streams"), patch.object(
                run_step.sys, "stderr", io.StringIO(),
            ):
                result = run_step._main_with_workflow_lock_held(
                    ["--step", "step1", "--project-dir", str(project), "--report-dir", str(report)],
                    _skip_environment_contract=True,
                )

        self.assertEqual(result, run_step.EXIT_AWAITING_USER)
        persist.assert_called_once_with(state, "step1", report, interaction)


class WindowsCompatibilityContractTest(unittest.TestCase):
    def test_windows_pid_probe_closes_handles_and_distinguishes_running_process(self):
        kernel = SimpleNamespace(
            OpenProcess=MagicMock(return_value=123),
            WaitForSingleObject=MagicMock(return_value=0x00000102),
            CloseHandle=MagicMock(return_value=1),
        )
        with patch.object(ctypes, "WinDLL", return_value=kernel, create=True):
            self.assertTrue(run_step._windows_pid_is_running(42))
        kernel.CloseHandle.assert_called_once_with(123)

        kernel.OpenProcess.return_value = 0
        with patch.object(ctypes, "WinDLL", return_value=kernel, create=True):
            self.assertFalse(run_step._windows_pid_is_running(42))
        with patch.object(ctypes, "WinDLL", side_effect=OSError("unavailable"), create=True):
            self.assertFalse(run_step._windows_pid_is_running(42))

    def test_windows_cleanup_rejects_links_and_removes_regular_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            nested = report / "runtime"
            nested.mkdir()
            target = nested / "result.txt"
            target.write_text("result", encoding="utf-8")
            observed = run_step._windows_cleanup_directory_stat(report)
            run_step._verify_windows_cleanup_bindings([(report, observed)])
            self.assertTrue(run_step._remove_step_output_windows_compat(
                report, Path("runtime/result.txt"), synchronize_parent=False,
            ))
            self.assertFalse(target.exists())
            self.assertFalse(run_step._remove_step_output_windows_compat(
                report, Path("runtime/missing.txt"),
            ))

            link = report / "link"
            try:
                link.symlink_to(nested, target_is_directory=True)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(OSError):
                run_step._windows_cleanup_directory_stat(link)


if __name__ == "__main__":
    unittest.main()
