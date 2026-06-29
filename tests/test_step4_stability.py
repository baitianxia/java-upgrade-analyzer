import json
import io
import sys
import tempfile
from pathlib import Path
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import compat  # noqa: E402
import auto_discover_bridge_sources as auto_sources  # noqa: E402
import run_step  # noqa: E402
import s4_jar_compare as step4  # noqa: E402


class Step4StabilityTest(unittest.TestCase):
    def test_step4_default_timeouts_are_unbounded(self):
        self.assertIsNone(step4.DEFAULT_GIT_DIFF_TIMEOUT)
        self.assertIsNone(step4.DEFAULT_JAPICMP_TIMEOUT)
        self.assertIsNone(step4.DEFAULT_FETCH_TIMEOUT)

    def test_run_gitdiff_uses_no_timeout_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "repo"
            repo_dir.mkdir(parents=True)
            (repo_dir / ".git").mkdir()
            lib_info = {
                "coord": "com.example:demo",
                "repo_path": str(repo_dir),
                "module_path": str(repo_dir),
                "old_version": "1.0.0",
                "new_version": "2.0.0",
            }
            captured = []

            def fake_run_cmd(cmd, cwd=None, timeout=None, **_kwargs):
                captured.append({"cmd": list(cmd), "cwd": cwd, "timeout": timeout})
                return "", "", 0

            with patch.object(
                step4,
                "resolve_repo_ref_pair_for_versions",
                return_value=("v1", "v2", "pair-old", "pair-new", [], []),
            ), \
                 patch.object(step4, "run_cmd", side_effect=fake_run_cmd):
                result = step4.run_gitdiff(lib_info, tmp)

        self.assertEqual(result["status"], "success")
        self.assertTrue(captured)
        self.assertIsNone(captured[0]["timeout"])

    def test_run_japicmp_uses_no_timeout_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            japicmp_jar = Path(tmp) / "japicmp.jar"
            old_jar = Path(tmp) / "old.jar"
            new_jar = Path(tmp) / "new.jar"
            japicmp_jar.write_text("stub", encoding="utf-8")
            old_jar.write_text("old", encoding="utf-8")
            new_jar.write_text("new", encoding="utf-8")
            captured = {}

            def fake_run_cmd(_cmd, _cwd=None, timeout=None, **_kwargs):
                captured["timeout"] = timeout
                return "", "", 0

            with patch.object(step4, "find_jar_in_m2", side_effect=[str(old_jar), str(new_jar)]), \
                 patch.object(step4, "run_cmd", side_effect=fake_run_cmd):
                step4.run_japicmp(
                    "com.example:demo",
                    "1.0.0",
                    "2.0.0",
                    tmp,
                    str(japicmp_jar),
                )

        self.assertIsNone(captured["timeout"])

    def test_run_japicmp_uses_old_and_new_flags_and_rejects_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            japicmp_jar = Path(tmp) / "japicmp.jar"
            old_jar = Path(tmp) / "old.jar"
            new_jar = Path(tmp) / "new.jar"
            japicmp_jar.write_text("stub", encoding="utf-8")
            old_jar.write_text("old", encoding="utf-8")
            new_jar.write_text("new", encoding="utf-8")

            with patch.object(step4, "find_jar_in_m2", side_effect=[str(old_jar), str(new_jar)]):
                with patch.object(
                    step4,
                    "run_cmd",
                    return_value=("See '--help' or '-h' for more information.\n", "E: Required option -o, --old is missing.\n", 1),
                ) as run_cmd_mock:
                    out_file, apis, jar_info, err = step4.run_japicmp(
                        "com.example:demo",
                        "1.0.0",
                        "2.0.0",
                        tmp,
                        str(japicmp_jar),
                    )
                    content = Path(out_file).read_text(encoding="utf-8")

        called_cmd = run_cmd_mock.call_args.args[0]
        self.assertIn("--old", called_cmd)
        self.assertIn("--new", called_cmd)
        self.assertNotIn("--old-classpath", called_cmd)
        self.assertNotIn("--new-classpath", called_cmd)
        self.assertEqual(apis, [])
        self.assertEqual(jar_info["old_jar"], str(old_jar))
        self.assertEqual(jar_info["new_jar"], str(new_jar))
        self.assertIn("Required option -o, --old is missing.", err)
        self.assertIn("JApiCmp 执行失败（退出码 1）", content)
        self.assertIn("stderr:", content)
        self.assertIn("stdout:", content)

    def test_run_japicmp_uses_distinct_old_and_new_coords_when_group_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            japicmp_jar = Path(tmp) / "japicmp.jar"
            old_jar = Path(tmp) / "old.jar"
            new_jar = Path(tmp) / "new.jar"
            japicmp_jar.write_text("stub", encoding="utf-8")
            old_jar.write_text("old", encoding="utf-8")
            new_jar.write_text("new", encoding="utf-8")

            with patch.object(
                step4,
                "find_jar_in_m2",
                side_effect=[str(old_jar), str(new_jar)],
            ) as find_jar_mock:
                with patch.object(step4, "run_cmd", return_value=("", "", 0)):
                    out_file, apis, jar_info, err = step4.run_japicmp(
                        "tools.jackson.core:jackson-core",
                        "2.14.1",
                        "3.0.4",
                        tmp,
                        str(japicmp_jar),
                        old_coord="com.fasterxml.jackson.core:jackson-core",
                        new_coord="tools.jackson.core:jackson-core",
                    )
                    content = Path(out_file).read_text(encoding="utf-8")

        self.assertIsNone(err)
        self.assertEqual(apis, [])
        self.assertEqual(jar_info["old_jar"], str(old_jar))
        self.assertEqual(jar_info["new_jar"], str(new_jar))
        self.assertEqual(
            find_jar_mock.call_args_list[0].args,
            ("com.fasterxml.jackson.core", "jackson-core", "2.14.1"),
        )
        self.assertEqual(
            find_jar_mock.call_args_list[1].args,
            ("tools.jackson.core", "jackson-core", "3.0.4"),
        )
        self.assertIn("旧坐标：com.fasterxml.jackson.core:jackson-core", content)
        self.assertIn("新坐标：tools.jackson.core:jackson-core", content)

    def test_resolve_repo_ref_for_version_requires_unique_remote_branch_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "heads": [],
                    "remotes": ["origin/release-1.0.0", "upstream/support-1.0.0"],
                    "tags": ["release-1.0.0", "v1.0.0"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "1.0.0")

        self.assertIsNone(resolved)
        self.assertEqual(reason, "ambiguous_ref_matches_for_version=1.0.0")
        self.assertEqual(
            [item["ref"] for item in candidates if item["score"] == 140],
            ["origin/release-1.0.0", "upstream/support-1.0.0"],
        )
        self.assertEqual([item["ref"] for item in candidates], ["origin/release-1.0.0", "upstream/support-1.0.0"])

    def test_resolve_repo_ref_for_version_matches_branch_name_containing_normalized_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/release-3.0.7-hotfix"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.7-SNAPSHOT")

        self.assertEqual(resolved, "origin/release-3.0.7-hotfix")
        self.assertEqual(reason, "matched_by_version(kind=remote,score=140,version=3.0.7)")
        self.assertEqual([item["ref"] for item in candidates], ["origin/release-3.0.7-hotfix"])

    def test_resolve_repo_ref_for_version_prefers_non_dev_branch_over_dev_branch(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/release-3.0.7-dev", "origin/release-3.0.7"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.7")

        self.assertEqual(resolved, "origin/release-3.0.7")
        self.assertEqual(reason, "matched_by_version(kind=remote,score=140,version=3.0.7)")
        self.assertEqual(
            [(item["ref"], item["score"]) for item in candidates],
            [("origin/release-3.0.7", 140), ("origin/release-3.0.7-dev", 130)],
        )

    def test_resolve_repo_ref_for_version_requires_manual_confirmation_when_full_version_not_contained(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/release/3.0.x", "origin/main"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.7-SNAPSHOT")

        self.assertIsNone(resolved)
        self.assertEqual(reason, "no_ref_match_for_version=3.0.7")
        self.assertEqual(candidates, [])

    def test_resolve_repo_ref_for_version_accepts_manual_override_when_no_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": [],
                },
            ):
                with patch.object(step4, "_git_ref_exists", return_value=True):
                    resolved, reason, candidates = step4.resolve_repo_ref_for_version(
                        tmp,
                        "3.5.14",
                        selected_ref="mybatis-3.5.14",
                    )

        self.assertEqual(resolved, "mybatis-3.5.14")
        self.assertEqual(reason, "selected_by_user(kind=manual,score=-1,version=3.5.14)")
        self.assertEqual(candidates, [])

    def test_resolve_repo_ref_for_version_accepts_branch_names_containing_exact_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": ["release-1.2.3"],
                    "heads": ["release/1.2.x"],
                    "remotes": ["origin/release-1.2.3", "origin/release/1.2.x", "origin/release-1.2.3-DEV"],
                },
            ):
                resolved_exact, reason_exact, candidates_exact = step4.resolve_repo_ref_for_version(tmp, "1.2.3")

        self.assertEqual(resolved_exact, "origin/release-1.2.3")
        self.assertEqual(reason_exact, "matched_by_version(kind=remote,score=140,version=1.2.3)")
        self.assertEqual(
            [(item["ref"], item["score"]) for item in candidates_exact],
            [("origin/release-1.2.3", 140), ("origin/release-1.2.3-DEV", 130)],
        )

    def test_resolve_repo_ref_for_version_requires_strict_boundary_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/auth-sdk3.0.2", "origin/auth-sdk3.0.2.1"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.2")

        self.assertEqual(resolved, "origin/auth-sdk3.0.2")
        self.assertEqual(reason, "matched_by_version(kind=remote,score=140,version=3.0.2)")
        self.assertEqual(
            [(item["ref"], item["score"], item["match_kind"]) for item in candidates],
            [
                ("origin/auth-sdk3.0.2", 140, "exact_boundary"),
            ],
        )

    def test_resolve_repo_ref_for_version_allows_separator_suffix_but_rejects_letter_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": ["origin/auth-sdk3.0.2-DEV", "origin/auth-sdk3.0.2SB3"],
                },
            ):
                resolved, reason, candidates = step4.resolve_repo_ref_for_version(tmp, "3.0.2")

        self.assertEqual(resolved, "origin/auth-sdk3.0.2-DEV")
        self.assertEqual(reason, "matched_by_version(kind=remote,score=130,version=3.0.2)")
        self.assertEqual(
            [(item["ref"], item["score"], item["match_kind"]) for item in candidates],
            [
                ("origin/auth-sdk3.0.2-DEV", 130, "exact_boundary"),
            ],
        )

    def test_resolve_repo_ref_pair_for_versions_prefers_same_prefix_family(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": [
                        "origin/auth-sdk3.0.2",
                        "origin/release-3.0.2",
                        "origin/auth-sdk3.12.0-SB3",
                    ],
                },
            ):
                (
                    resolved_old,
                    resolved_new,
                    old_reason,
                    new_reason,
                    old_candidates,
                    new_candidates,
                ) = step4.resolve_repo_ref_pair_for_versions(tmp, "3.0.2", "3.12.0-SB3")

        self.assertEqual(resolved_old, "origin/auth-sdk3.0.2")
        self.assertEqual(resolved_new, "origin/auth-sdk3.12.0-SB3")
        self.assertIn("matched_by_version_pair(", old_reason)
        self.assertIn("matched_by_version_pair(", new_reason)
        self.assertIn("same_prefix=true", old_reason)
        self.assertIn("same_remote=true", old_reason)
        self.assertEqual(
            [item["ref"] for item in old_candidates],
            ["origin/auth-sdk3.0.2", "origin/release-3.0.2"],
        )
        self.assertEqual(
            [item["ref"] for item in new_candidates],
            ["origin/auth-sdk3.12.0-SB3"],
        )

    def test_resolve_repo_ref_pair_for_versions_prefers_pair_delta_matching_version_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": [
                        "origin/acct-sdk3.0.8",
                        "origin/acct-sdk3.0.8-SB3",
                    ],
                },
            ):
                (
                    resolved_old,
                    resolved_new,
                    old_reason,
                    new_reason,
                    old_candidates,
                    new_candidates,
                ) = step4.resolve_repo_ref_pair_for_versions(tmp, "3.0.8-SNAPSHOT", "3.0.8-SB3-SNAPSHOT")

        self.assertEqual(resolved_old, "origin/acct-sdk3.0.8")
        self.assertEqual(resolved_new, "origin/acct-sdk3.0.8-SB3")
        self.assertIn("delta_match=exact", old_reason)
        self.assertIn("delta_match=exact", new_reason)
        self.assertEqual(
            [item["ref"] for item in old_candidates],
            ["origin/acct-sdk3.0.8", "origin/acct-sdk3.0.8-SB3"],
        )
        self.assertEqual(
            [item["ref"] for item in new_candidates],
            ["origin/acct-sdk3.0.8-SB3"],
        )

    def test_resolve_repo_ref_pair_for_versions_matches_generic_token_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4,
                "_list_repo_refs",
                return_value={
                    "tags": [],
                    "heads": [],
                    "remotes": [
                        "origin/acct-sdk-ee8-3.0.8",
                        "origin/acct-sdk-ee9-3.0.8",
                        "origin/acct-sdk3.0.8",
                    ],
                },
            ):
                (
                    resolved_old,
                    resolved_new,
                    old_reason,
                    new_reason,
                    _old_candidates,
                    _new_candidates,
                ) = step4.resolve_repo_ref_pair_for_versions(tmp, "3.0.8-EE8", "3.0.8-EE9")

        self.assertEqual(resolved_old, "origin/acct-sdk-ee8-3.0.8")
        self.assertEqual(resolved_new, "origin/acct-sdk-ee9-3.0.8")
        self.assertIn("delta_match=exact", old_reason)
        self.assertIn("delta_match=exact", new_reason)

    def test_infer_maven_coord_locations_scans_more_than_80_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for idx in range(120):
                module_dir = root / f"module-{idx:03d}"
                module_dir.mkdir(parents=True)
                (module_dir / "pom.xml").write_text(
                    "\n".join(
                        [
                            "<project>",
                            "  <modelVersion>4.0.0</modelVersion>",
                            f"  <groupId>com.example</groupId>",
                            f"  <artifactId>module-{idx:03d}</artifactId>",
                            "  <version>1.0.0</version>",
                            "</project>",
                        ]
                    ),
                    encoding="utf-8",
                )

            locations = compat.infer_maven_coord_locations(str(root))
            coords = [item.get("coord") for item in locations if item.get("coord")]
            self.assertEqual(len(coords), 120)
            self.assertEqual(coords[0], "com.example:module-000")
            self.assertEqual(coords[-1], "com.example:module-119")

    def test_infer_maven_coord_locations_infers_gradle_submodule_group_from_repo_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            module_dir = root / "core" / "spring-boot-autoconfigure"
            module_dir.mkdir(parents=True)
            (module_dir / "build.gradle").write_text(
                'description = "Spring Boot AutoConfigure"\n',
                encoding="utf-8",
            )

            locations = compat.infer_maven_coord_locations(str(root))
            by_coord = {item.get("coord"): item for item in locations if item.get("coord")}

        self.assertIn("org.springframework.boot:spring-boot-autoconfigure", by_coord)
        self.assertEqual(
            by_coord["org.springframework.boot:spring-boot-autoconfigure"]["module_dir"],
            str(module_dir.resolve()),
        )
        self.assertEqual(
            by_coord["org.springframework.boot:spring-boot-autoconfigure"]["repo_root"],
            str(root.resolve()),
        )

    def test_infer_maven_coord_locations_skips_aggregate_root_without_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            module_dir = root / "core" / "spring-boot"
            module_dir.mkdir(parents=True)
            (module_dir / "build.gradle").write_text(
                'description = "Spring Boot"\n',
                encoding="utf-8",
            )
            (module_dir / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)

            locations = compat.infer_maven_coord_locations(str(root))
            spring_boot_locations = [
                item for item in locations if item.get("coord") == "org.springframework.boot:spring-boot"
            ]

        self.assertEqual(len(spring_boot_locations), 1)
        self.assertEqual(
            spring_boot_locations[0]["module_dir"],
            str(module_dir.resolve()),
        )

    def test_infer_maven_coord_locations_skips_embedded_resource_sample_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "com.example"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            module_dir = root / "core" / "demo"
            module_dir.mkdir(parents=True)
            (module_dir / "build.gradle").write_text('description = "Demo"\n', encoding="utf-8")
            (module_dir / "src" / "main" / "java" / "com" / "example").mkdir(parents=True)

            sample_dir = root / "buildSrc" / "src" / "test" / "resources" / "samples" / "spring-boot-project" / "spring-boot"
            sample_dir.mkdir(parents=True)
            (sample_dir / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (sample_dir / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)

            locations = compat.infer_maven_coord_locations(str(root))
            coords = {item.get("coord") for item in locations if item.get("coord")}

        self.assertIn("com.example:demo", coords)
        self.assertNotIn("org.springframework.boot:spring-boot", coords)

    def test_discover_bridge_source_mappings_skips_embedded_resource_sample_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "com.example"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            module_dir = root / "core" / "demo"
            module_dir.mkdir(parents=True)
            (module_dir / "build.gradle").write_text('description = "Demo"\n', encoding="utf-8")
            (module_dir / "src" / "main" / "java" / "com" / "example").mkdir(parents=True)
            (module_dir / "src" / "main" / "java" / "com" / "example" / "Demo.java").write_text(
                "package com.example;\nclass Demo {}\n",
                encoding="utf-8",
            )

            sample_dir = root / "buildSrc" / "src" / "test" / "resources" / "samples" / "spring-boot-project" / "spring-boot"
            sample_dir.mkdir(parents=True)
            (sample_dir / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (sample_dir / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)
            (sample_dir / "src" / "main" / "java" / "org" / "springframework" / "boot" / "Sample.java").write_text(
                "package org.springframework.boot;\nclass Sample {}\n",
                encoding="utf-8",
            )

            mappings = auto_sources.discover_bridge_source_mappings("", str(root))
            coords = {coord for coord, _source_dir in mappings}

        self.assertIn("com.example:demo", coords)
        self.assertNotIn("org.springframework.boot:spring-boot", coords)

    def test_infer_maven_coord_locations_does_not_scan_sibling_repo_from_workspace_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / ".git").mkdir()

            security_repo = workspace / "_dependency_sources" / "spring-security"
            security_repo.mkdir(parents=True)
            (security_repo / ".git").mkdir()
            (security_repo / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.security"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            security_module = security_repo / "web"
            security_module.mkdir()
            (security_module / "build.gradle").write_text('description = "Web"\n', encoding="utf-8")
            (security_module / "src" / "main" / "java" / "org" / "springframework" / "security").mkdir(parents=True)

            boot_repo = workspace / "_dependency_sources" / "spring-boot"
            boot_repo.mkdir(parents=True)
            (boot_repo / ".git").mkdir()
            (boot_repo / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            boot_module = boot_repo / "spring-boot-project" / "spring-boot"
            boot_module.mkdir(parents=True)
            (boot_module / "build.gradle").write_text('description = "Spring Boot"\n', encoding="utf-8")
            (boot_module / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)

            coords = {
                item.get("coord")
                for item in compat.infer_maven_coord_locations(str(security_repo))
                if item.get("coord")
            }

        self.assertIn("org.springframework.security:web", coords)
        self.assertNotIn("org.springframework.boot:spring-boot", coords)

    def test_infer_maven_coord_locations_supports_named_gradle_module_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.security"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            core_dir = root / "core"
            core_dir.mkdir(parents=True)
            (core_dir / "spring-security-core.gradle").write_text(
                "description = 'Core'\n",
                encoding="utf-8",
            )
            (core_dir / "src" / "main" / "java" / "org" / "springframework" / "security" / "core").mkdir(parents=True)

            by_coord = {
                item.get("coord"): item
                for item in compat.infer_maven_coord_locations(str(root))
                if item.get("coord")
            }

        self.assertIn("org.springframework.security:spring-security-core", by_coord)
        self.assertEqual(
            by_coord["org.springframework.security:spring-security-core"]["module_dir"],
            str(core_dir.resolve()),
        )

    def test_infer_maven_coord_locations_ignores_task_group_assignment_when_inferring_group_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.security"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            web_dir = root / "web"
            web_dir.mkdir(parents=True)
            (web_dir / "spring-security-web.gradle").write_text(
                "\n".join(
                    [
                        "tasks.register('syncJavascript') {",
                        "    group = 'Build'",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            (web_dir / "src" / "main" / "java" / "org" / "springframework" / "security" / "web").mkdir(parents=True)

            by_coord = {
                item.get("coord"): item
                for item in compat.infer_maven_coord_locations(str(root))
                if item.get("coord")
            }

        self.assertIn("org.springframework.security:spring-security-web", by_coord)
        self.assertEqual(
            by_coord["org.springframework.security:spring-security-web"]["module_dir"],
            str(web_dir.resolve()),
        )

    def test_infer_maven_coord_locations_prioritizes_main_gradle_modules_before_test_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / "build.gradle").write_text(
                "\n".join(
                    [
                        "configure(allprojects) { project ->",
                        '    group = "org.springframework.boot"',
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            boot_dir = root / "spring-boot-project" / "spring-boot"
            boot_dir.mkdir(parents=True)
            (boot_dir / "build.gradle").write_text("description = 'Spring Boot'\n", encoding="utf-8")
            (boot_dir / "src" / "main" / "java" / "org" / "springframework" / "boot").mkdir(parents=True)

            auto_dir = root / "spring-boot-project" / "spring-boot-autoconfigure"
            auto_dir.mkdir(parents=True)
            (auto_dir / "build.gradle").write_text(
                "description = 'Spring Boot AutoConfigure'\n",
                encoding="utf-8",
            )
            (auto_dir / "src" / "main" / "java" / "org" / "springframework" / "boot" / "autoconfigure").mkdir(parents=True)

            for index in range(20):
                smoke_dir = root / "spring-boot-tests" / "spring-boot-smoke-tests" / f"spring-boot-smoke-test-{index:02d}"
                smoke_dir.mkdir(parents=True)
                (smoke_dir / "build.gradle").write_text(
                    f"description = 'Smoke {index}'\n",
                    encoding="utf-8",
                )
                (smoke_dir / "src" / "main" / "java" / "com" / "example").mkdir(parents=True)

            coords = compat.infer_maven_coords(str(root), max_poms=2)

        self.assertEqual(
            coords,
            [
                "org.springframework.boot:spring-boot",
                "org.springframework.boot:spring-boot-autoconfigure",
            ],
        )

    def test_is_ephemeral_dependency_source_mapping_detects_hoisted_workspace_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / ".git").mkdir()
            module_dir = (
                workspace
                / ".tmp-validation"
                / "dependency-sources"
                / "org.yaml__snakeyaml__1.30"
                / "META-INF"
                / "maven"
                / "org.yaml"
                / "snakeyaml"
            )
            module_dir.mkdir(parents=True)

            self.assertTrue(
                step4.is_ephemeral_dependency_source_mapping(
                    {
                        "repo_path": str(workspace),
                        "module_path": str(module_dir),
                    }
                )
            )
            self.assertFalse(
                step4.is_ephemeral_dependency_source_mapping(
                    {
                        "repo_path": str(module_dir),
                        "module_path": str(module_dir),
                    }
                )
            )

    def test_extract_api_signature_handles_nested_annotations_and_kotlin_style(self):
        java_decl = "public void update(@Named(value = \"user\", required = true) List<Map<String, Long>> users, String[] tags)"
        kotlin_decl = "fun update(user: Map<String, List<Long>>, tag: String? = \"x\")"

        self.assertEqual(
            step4.extract_api_signature_from_declaration(java_decl),
            "(List<Map<String, Long>>, String[])",
        )
        self.assertEqual(
            step4.extract_api_signature_from_declaration(kotlin_decl),
            "(Map<String, List<Long>>, String?)",
        )

    def test_extract_api_signature_returns_unit_tuple_for_noarg_method(self):
        self.assertEqual(
            step4.extract_api_signature_from_declaration("public static void removeAll() {"),
            "()",
        )

    def test_run_gitdiff_requests_user_confirmation_when_refs_unresolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp)
            (repo_dir / ".git").mkdir()
            output_dir = repo_dir / "out"
            output_dir.mkdir()

            with patch.object(step4, "resolve_repo_ref_for_version", side_effect=[(None, "miss-old", []), (None, "miss-new", [])]):
                with patch.object(step4, "_list_repo_refs", return_value={"tags": ["v1.0.0"], "heads": [], "remotes": ["origin/2.0.0"]}):
                    result = step4.run_gitdiff(
                        {
                            "coord": "com.example:demo",
                            "repo_path": str(repo_dir),
                            "module_path": str(repo_dir),
                            "old_version": "1.0.0",
                            "new_version": "2.0.0",
                        },
                        str(output_dir),
                    )

            self.assertEqual(result["status"], "needs_user_confirmation")
            self.assertEqual(result["error"], "无法定位对比 ref")
            self.assertEqual(result["meta"]["coord"], "com.example:demo")

    def test_parse_gitdiff_apis_resets_scope_for_sibling_class(self):
        diff_output = "\n".join(
            [
                "diff --git a/src/main/java/com/example/Foo.java b/src/main/java/com/example/Foo.java",
                "--- a/src/main/java/com/example/Foo.java",
                "+++ b/src/main/java/com/example/Foo.java",
                "@@",
                " package com.example;",
                " class Outer {",
                "     class Inner {",
                "     }",
                " }",
                " class Sibling {",
                "-    public void ping(String value) {",
                "+    public void ping(Integer value) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "com.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "com.example.Sibling.ping")
        self.assertEqual(apis[0]["change_type"], "SIGNATURE_CHANGED")
        self.assertEqual(apis[0]["api_signature"], "(String)")

    def test_parse_gitdiff_apis_skips_test_source_files(self):
        diff_output = "\n".join(
            [
                "diff --git a/common/src/test/java/io/netty/util/RecyclerTest.java b/common/src/test/java/io/netty/util/RecyclerTest.java",
                "--- a/common/src/test/java/io/netty/util/RecyclerTest.java",
                "+++ b/common/src/test/java/io/netty/util/RecyclerTest.java",
                "@@",
                " package io.netty.util;",
                "-public class RecyclerTest {",
                "+public class RecyclerTest {",
                "-    public void run(int threads) {",
                "+    public void run(int threads, int batchSize) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "io.netty:netty-common", "4.1.83.Final", "4.1.89.Final")

        self.assertEqual(apis, [])

    def test_parse_gitdiff_apis_skips_root_relative_test_source_files(self):
        diff_output = "\n".join(
            [
                "diff --git a/src/test/java/org/apache/ibatis/submitted/awful_table/AwfulTable.java b/src/test/java/org/apache/ibatis/submitted/awful_table/AwfulTable.java",
                "--- a/src/test/java/org/apache/ibatis/submitted/awful_table/AwfulTable.java",
                "+++ b/src/test/java/org/apache/ibatis/submitted/awful_table/AwfulTable.java",
                "@@",
                " package org.apache.ibatis.submitted.awful_table;",
                "-public class AwfulTable {",
                "+public class AwfulTable {",
                "-    public void setCustomerId(Integer id) {",
                "+    public void setCustomerId(Long id) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "org.mybatis:mybatis", "3.5.9", "3.5.14")

        self.assertEqual(apis, [])

    def test_parse_gitdiff_apis_skips_build_support_files(self):
        diff_output = "\n".join(
            [
                "diff --git a/.mvn/wrapper/MavenWrapperDownloader.java b/.mvn/wrapper/MavenWrapperDownloader.java",
                "--- a/.mvn/wrapper/MavenWrapperDownloader.java",
                "+++ b/.mvn/wrapper/MavenWrapperDownloader.java",
                "@@",
                " package .mvn.wrapper;",
                "-public class MavenWrapperDownloader {",
                "+public class MavenWrapperDownloader {",
                "-    public void run(String url) {",
                "+    public void run(String url, String checksum) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "org.mybatis:mybatis", "3.5.9", "3.5.14")

        self.assertEqual(apis, [])

    def test_parse_gitdiff_apis_collects_multiline_method_signature(self):
        diff_output = "\n".join(
            [
                "diff --git a/common/src/main/java/io/netty/util/concurrent/FastThreadLocal.java b/common/src/main/java/io/netty/util/concurrent/FastThreadLocal.java",
                "--- a/common/src/main/java/io/netty/util/concurrent/FastThreadLocal.java",
                "+++ b/common/src/main/java/io/netty/util/concurrent/FastThreadLocal.java",
                "@@",
                " package io.netty.util.concurrent;",
                " public final class FastThreadLocal<V> {",
                "     private static void removeFromVariablesToRemove(",
                "             InternalThreadLocalMap threadLocalMap, FastThreadLocal<?> variable) {",
                "-        Object v = threadLocalMap.indexedVariable(variablesToRemoveIndex);",
                "+        Object v = threadLocalMap.removeIndexedVariable(variablesToRemoveIndex);",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "io.netty:netty-common", "4.1.83.Final", "4.1.89.Final")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "io.netty.util.concurrent.FastThreadLocal.removeFromVariablesToRemove")
        self.assertEqual(apis[0]["api_signature"], "(InternalThreadLocalMap, FastThreadLocal<?>)")

    def test_parse_gitdiff_apis_detects_kotlin_method_with_explicit_visibility(self):
        diff_output = "\n".join(
            [
                "diff --git a/src/main/kotlin/com/example/Demo.kt b/src/main/kotlin/com/example/Demo.kt",
                "--- a/src/main/kotlin/com/example/Demo.kt",
                "+++ b/src/main/kotlin/com/example/Demo.kt",
                "@@",
                " package com.example",
                " class Demo {",
                "-    public fun load(name: String) {",
                "+    public fun load(id: Long) {",
                "     }",
                " }",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "com.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "com.example.Demo.load")
        self.assertEqual(apis[0]["change_type"], "SIGNATURE_CHANGED")
        self.assertEqual(apis[0]["api_signature"], "(String)")

    def test_parse_japicmp_output_prefers_terminal_method_in_chained_expression(self):
        output = (
            "***! MODIFIED METHOD: "
            "org.example.XmlUtil.from(java.lang.String)."
            "to(java.lang.String)."
            "UniversalNamespaceCache.getPrefixes()"
        )

        apis = step4.parse_japicmp_output(output, "org.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(
            apis[0]["api_name"],
            "org.example.UniversalNamespaceCache.getPrefixes",
        )
        self.assertEqual(apis[0]["api_signature"], "()")
        self.assertEqual(apis[0]["source"], "japicmp")

    def test_parse_japicmp_output_keeps_regular_method_signature(self):
        output = "***! REMOVED METHOD: org.example.Foo.load(java.lang.String, int[])"

        apis = step4.parse_japicmp_output(output, "org.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "org.example.Foo.load")
        self.assertEqual(apis[0]["api_signature"], "(java.lang.String, int[])")
        self.assertEqual(apis[0]["change_type"], "REMOVED")

    def test_parse_japicmp_output_uses_declaring_type_for_h2_removed_method(self):
        output = "\n".join(
            [
                "***! MODIFIED INTERFACE: PUBLIC ABSTRACT org.h2.command.CommandInterface  (not serializable)",
                "---! REMOVED METHOD: PUBLIC(-) ABSTRACT(-) org.h2.result.ResultInterface executeQuery(int, boolean)",
            ]
        )

        apis = step4.parse_japicmp_output(output, "com.h2database:h2", "1.4.200", "2.1.214")

        self.assertEqual(len(apis), 2)
        self.assertEqual(apis[1]["api_name"], "org.h2.command.CommandInterface.executeQuery")
        self.assertEqual(apis[1]["api_signature"], "(int, boolean)")
        self.assertEqual(apis[1]["symbol_kind"], "method")
        self.assertEqual(apis[1]["change_type"], "REMOVED")

    def test_parse_japicmp_output_uses_declaring_type_for_h2_modified_method(self):
        output = "\n".join(
            [
                "***! MODIFIED INTERFACE: PUBLIC ABSTRACT org.h2.api.Aggregate  (not serializable)",
                "***! MODIFIED METHOD: PUBLIC NON_ABSTRACT (<- ABSTRACT) void init(java.sql.Connection)",
            ]
        )

        apis = step4.parse_japicmp_output(output, "com.h2database:h2", "1.4.200", "2.1.214")

        self.assertEqual(len(apis), 2)
        self.assertEqual(apis[1]["api_name"], "org.h2.api.Aggregate.init")
        self.assertEqual(apis[1]["api_signature"], "(java.sql.Connection)")
        self.assertEqual(apis[1]["symbol_kind"], "method")
        self.assertEqual(apis[1]["change_type"], "SIGNATURE_CHANGED")

    def test_parse_japicmp_output_uses_declaring_type_for_removed_constructor(self):
        output = "\n".join(
            [
                "---! REMOVED CLASS: PUBLIC(-) FINAL(-) org.h2.api.TimestampWithTimeZone  (class removed)",
                "\t---! REMOVED INTERFACE: java.lang.Cloneable",
                "\t---! REMOVED INTERFACE: java.io.Serializable",
                "---! REMOVED CONSTRUCTOR: PUBLIC(-) TimestampWithTimeZone(long, long, short)",
            ]
        )

        apis = step4.parse_japicmp_output(output, "com.h2database:h2", "1.4.200", "2.1.214")

        self.assertEqual(len(apis), 2)
        self.assertEqual(
            apis[1]["api_name"],
            "org.h2.api.TimestampWithTimeZone.TimestampWithTimeZone",
        )
        self.assertEqual(apis[1]["api_signature"], "(long, long, short)")
        self.assertEqual(apis[1]["symbol_kind"], "constructor")
        self.assertEqual(apis[1]["change_type"], "REMOVED")
        self.assertEqual(apis[0]["api_name"], "org.h2.api.TimestampWithTimeZone")

    def test_parse_japicmp_output_uses_declaring_type_for_modified_field(self):
        output = "\n".join(
            [
                "***! MODIFIED CLASS: PUBLIC ABSTRACT org.h2.command.Command  (not serializable)",
                "***! MODIFIED FIELD: PROTECTED FINAL org.h2.engine.SessionLocal (<- org.h2.engine.Session) session",
            ]
        )

        apis = step4.parse_japicmp_output(output, "com.h2database:h2", "1.4.200", "2.1.214")

        self.assertEqual(len(apis), 2)
        self.assertEqual(apis[1]["api_name"], "org.h2.command.Command.session")
        self.assertEqual(apis[1]["api_signature"], "")
        self.assertEqual(apis[1]["symbol_kind"], "field")
        self.assertEqual(apis[1]["change_type"], "SIGNATURE_CHANGED")

    def test_parse_gitdiff_apis_ignores_comment_text_when_tracking_class_scope(self):
        diff_output = "\n".join(
            [
                "diff --git a/src/main/java/org/example/Real.java b/src/main/java/org/example/Real.java",
                "--- a/src/main/java/org/example/Real.java",
                "+++ b/src/main/java/org/example/Real.java",
                "@@",
                " package org.example;",
                "+ // object FakeObject",
                "-    public void load(String value) {",
                "+    public void load(Integer value) {",
            ]
        )

        apis = step4.parse_gitdiff_apis(diff_output, "com.example:demo", "1.0.0", "2.0.0")

        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["api_name"], "org.example.Real.load")
        self.assertEqual(apis[0]["api_signature"], "(String)")

    def test_write_git_ref_match_outputs_marks_confirmation_only_when_pending_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path, txt_path = step4.write_git_ref_match_outputs(
                output_dir=tmp,
                gitdiff_runs=[
                    {
                        "coord": "com.example:demo",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "base_ref": "v1.0.0",
                        "cur_ref": "v2.0.0",
                        "old_match_reason": "matched",
                        "new_match_reason": "matched",
                        "old_candidates": [{"ref": "v1.0.0"}],
                        "new_candidates": [{"ref": "v2.0.0"}],
                    }
                ],
                gitdiff_pending=[],
                gitdiff_skipped=[],
                source_repo_mappings=[],
            )
            payload = json.loads(Path(json_path).read_text(encoding="utf-8"))
            text = Path(txt_path).read_text(encoding="utf-8")

        self.assertFalse(payload["need_user_confirmation"])
        self.assertIn("已自动匹配，可抽查", text)

    def test_cleanup_step4_generated_outputs_removes_stale_generated_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            stale_gitdiff = output_dir / "demo-lib_gitdiff_api_changes.txt"
            stale_summary = output_dir / "summary.txt"
            unrelated = output_dir / "keep.me"
            stale_gitdiff.write_text("old diff", encoding="utf-8")
            stale_summary.write_text("old summary", encoding="utf-8")
            unrelated.write_text("keep", encoding="utf-8")

            step4.cleanup_step4_generated_outputs(output_dir)

            self.assertFalse(stale_gitdiff.exists())
            self.assertFalse(stale_summary.exists())
            self.assertTrue(unrelated.exists())

    def test_main_removed_dependency_exports_old_jar_symbols_and_writes_per_dependency_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            output_dir = report_dir / "s4_jar_compare"
            dep_changes.write_text(
                "\n".join(
                    [
                        "coord,old_version,new_version,change_type,scope,base_coord",
                        "com.example:legacy-lib,1.0.0,-,移除,compile,com.example:legacy-lib",
                    ]
                ),
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps({"changed_dependencies": [{"coord": "com.example:legacy-lib"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            removed_api = {
                "coord": "com.example:legacy-lib",
                "old_version": "1.0.0",
                "new_version": "-",
                "change_type": "REMOVED",
                "api_name": "com.example.LegacyApi.call",
                "api_simple": "call",
                "symbol_kind": "method",
                "api_signature": "()",
                "confirmed": "true",
                "severity": "P0",
                "source": "old_jar",
            }

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes",
                    str(dep_changes),
                    "--context",
                    str(context_json),
                    "--output-dir",
                    str(output_dir),
                ],
            ), patch.object(
                step4,
                "export_removed_jar_apis",
                return_value=(
                    str(output_dir / "legacy_removed_symbols.txt"),
                    [removed_api],
                    {"old_jar": str(report_dir / "legacy-1.0.0.jar"), "errors": []},
                    None,
                ),
            ) as export_mock:
                exit_code = step4.main()

            self.assertEqual(exit_code, 0)
            export_mock.assert_called_once()
            per_dependency_dir = step4.get_per_dependency_dir(str(report_dir), "com.example:legacy-lib")
            removed_symbols_csv = per_dependency_dir / step4.PER_DEPENDENCY_REMOVED_JAR_SYMBOLS_FILE
            resolved_targets_csv = per_dependency_dir / step4.PER_DEPENDENCY_RESOLVED_TARGETS_FILE
            summary_json = per_dependency_dir / step4.PER_DEPENDENCY_SUMMARY_FILE

            self.assertTrue(removed_symbols_csv.exists())
            self.assertTrue(resolved_targets_csv.exists())
            self.assertTrue(summary_json.exists())
            self.assertIn("com.example.LegacyApi.call", removed_symbols_csv.read_text(encoding="utf-8"))
            self.assertIn("com.example.LegacyApi.call", resolved_targets_csv.read_text(encoding="utf-8"))
            summary = json.loads(summary_json.read_text(encoding="utf-8"))
            self.assertEqual(summary["coord"], "com.example:legacy-lib")
            self.assertEqual(summary["step4"]["removed_jar_symbol_count"], 1)
            self.assertEqual(summary["step4"]["removed_jar"]["old_jar"], str(report_dir / "legacy-1.0.0.jar"))

    def test_step4_emits_progress_logs_for_long_running_phases(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            dep_changes = report_dir / "s1_dep_changes.csv"
            context_json = report_dir / "s2_context.json"
            output_dir = report_dir / "s4_jar_compare"
            dep_changes.write_text(
                "\n".join(
                    [
                        "coord,old_version,new_version,change_type,scope",
                        "com.example:demo,1.0.0,2.0.0,小版本升级,compile",
                    ]
                ),
                encoding="utf-8",
            )
            context_json.write_text(
                json.dumps({"changed_dependencies": [{"coord": "com.example:demo"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            stderr = io.StringIO()

            with patch.object(
                sys,
                "argv",
                [
                    "s4_jar_compare.py",
                    "--dep-changes",
                    str(dep_changes),
                    "--context",
                    str(context_json),
                    "--output-dir",
                    str(output_dir),
                ],
            ), patch.object(
                step4,
                "run_japicmp",
                return_value=(str(output_dir / "demo_binary.txt"), [], {"old_jar": "", "new_jar": ""}, None),
            ), patch.object(
                step4,
                "write_all_changed_apis",
                return_value=(str(output_dir / "all_changed_apis.csv"), 0, 0),
            ), patch.object(
                step4,
                "write_readable_outputs",
                return_value=(str(output_dir / "all_changed_apis_alerts.csv"), str(output_dir / "summary.txt")),
            ), patch.object(
                step4,
                "write_git_ref_match_outputs",
                return_value=(str(output_dir / "git_ref_matches.json"), str(output_dir / "git_ref_matches.txt")),
            ), patch.object(
                step4,
                "human_checkpoint_1",
            ), redirect_stderr(stderr):
                exit_code = step4.main()

        output = stderr.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("[progress][step4][plan]", output)
        self.assertIn("[progress][step4][dependency]", output)
        self.assertIn("[progress][step4][japicmp]", output)
        self.assertIn("[progress][step4][done]", output)

    def test_step4_timeout_rerun_requires_timeout_override(self):
        pending_interaction = {
            "step_id": "step4",
            "reason_code": "step4_timeouts_need_resolution",
        }
        with self.assertRaises(run_step.StepError):
            run_step.validate_pending_interaction_response(
                pending_interaction,
                {"action": "rerun_current_step"},
            )

        run_step.validate_pending_interaction_response(
            pending_interaction,
            {
                "action": "rerun_current_step",
                "step4_git_diff_timeout": 240,
            },
        )

    def test_step4_timeout_rerun_accepts_dependency_source_dirs_fix(self):
        pending_interaction = {
            "step_id": "step4",
            "reason_code": "step4_timeouts_need_resolution",
        }

        run_step.validate_pending_interaction_response(
            pending_interaction,
            {
                "action": "rerun_current_step",
                "dependency_source_dirs": ["/tmp/dependency-repo"],
            },
        )

    def test_normalize_dependency_git_ref_overrides(self):
        payload = [
            {"coord": "com.foo:bar", "old_ref": "v1", "new_ref": "v2"},
            {"coord": "com.foo:baz", "old_ref": "release-1", "new_ref": "release-2"},
        ]
        normalized = run_step.normalize_dependency_git_ref_overrides(payload)
        self.assertEqual(normalized, payload)

        normalized_from_json = run_step.normalize_dependency_git_ref_overrides(json.dumps(payload, ensure_ascii=False))
        self.assertEqual(normalized_from_json, payload)

    def test_step4_rerun_requires_git_ref_overrides(self):
        pending_interaction = {
            "step_id": "step4",
            "reason_code": "step4_git_refs_need_confirmation",
        }
        with self.assertRaises(run_step.StepError):
            run_step.validate_pending_interaction_response(
                pending_interaction,
                {"action": "rerun_current_step"},
            )

        run_step.validate_pending_interaction_response(
            pending_interaction,
            {
                "action": "rerun_current_step",
                "dependency_git_ref_overrides": [
                    {"coord": "com.foo:bar", "old_ref": "v1", "new_ref": "v2"}
                ],
            },
        )

    def test_step4_rerun_accepts_dependency_source_dirs_fix(self):
        pending_interaction = {
            "step_id": "step4",
            "reason_code": "step4_git_refs_need_confirmation",
        }

        run_step.validate_pending_interaction_response(
            pending_interaction,
            {
                "action": "rerun_current_step",
                "dependency_source_dirs": ["/tmp/dependency-repo"],
            },
        )


if __name__ == "__main__":
    unittest.main()
