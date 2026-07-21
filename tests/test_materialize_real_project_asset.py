import json
import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import materialize_real_project_asset as materializer  # noqa: E402


class MaterializeRealProjectAssetTest(unittest.TestCase):
    def test_source_build_plan_is_revision_scoped_and_never_uses_a_shell(self):
        manifest = {
            "case": "source-case",
            "materialization": {
                "kind": "source_build",
                "repository_url": "https://github.com/example/project.git",
                "working_directory": "complete",
                "command": ["mvn", "-q", "-DskipTests", "package"],
                "artifacts": [{
                    "revision": "a" * 40,
                    "artifact_path": "target/app.jar",
                    "artifact_sha256": "b" * 64,
                }],
            },
        }

        with tempfile.TemporaryDirectory() as tmp:
            plan = materializer.build_materialization_plan(manifest, Path(tmp))

        self.assertEqual(plan[0]["operation"], "git_clone")
        self.assertEqual(plan[1]["argv"], ["git", "checkout", "--detach", "a" * 40])
        self.assertEqual(plan[2]["argv"], ["mvn", "-q", "-DskipTests", "package"])
        self.assertNotIn("shell", plan[2])
        self.assertTrue(plan[-1]["destination"].endswith("source-case/" + "a" * 40 + "/app.jar"))

    def test_v4_source_build_plan_records_runtime_artifact_without_historical_sha(self):
        manifest = {
            "schema": "java-upgrade-analyzer.real-project-guard.v4",
            "case": "source-case",
            "guard_lifecycle": "core",
            "capability_ids": ["business_direct"],
            "required_topologies": ["business_direct"],
            "git_revision": "a" * 40,
            "artifact_path": "target/app.jar",
            "canonical_edge_binding": "semantic",
            "materialization": {
                "kind": "source_build",
                "artifact_verification": "runtime",
                "repository_url": "https://github.com/example/project.git",
                "working_directory": ".",
                "command": ["mvn", "package"],
                "artifact_path": "target/app.jar",
            },
        }

        with tempfile.TemporaryDirectory() as tmp:
            plan = materializer.build_materialization_plan(manifest, Path(tmp))

        self.assertEqual(plan[-1]["operation"], "copy_artifact")
        self.assertNotIn("sha256", plan[-1])

    def test_runtime_copy_reports_the_actual_artifact_sha(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.jar"
            destination = Path(tmp) / "out" / "source.jar"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("app/App.class", b"class")
            expected_sha = hashlib.sha256(source.read_bytes()).hexdigest()

            artifacts = materializer.execute_materialization_plan([{
                "operation": "copy_artifact",
                "source": str(source),
                "destination": str(destination),
            }])

        self.assertEqual(artifacts, [{
            "path": str(destination),
            "sha256": expected_sha,
            "verification": "runtime",
        }])

    def test_published_plan_downloads_to_sha_scoped_destination(self):
        manifest = {
            "case": "published-case",
            "materialization": {
                "kind": "published_artifact",
                "coordinate": "g:a:1",
                "url": "https://repo.example/g/a/1/a-1.jar",
                "sha1": "a" * 40,
                "sha256": "b" * 64,
            },
        }

        with tempfile.TemporaryDirectory() as tmp:
            plan = materializer.build_materialization_plan(manifest, Path(tmp))

        self.assertEqual([item["operation"] for item in plan], ["download", "verify"])
        self.assertTrue(plan[0]["destination"].endswith("published-case/" + "b" * 16 + "/a-1.jar"))
        self.assertEqual(plan[1]["sha256"], "b" * 64)

    def test_cli_rejects_manifest_without_reproducible_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(json.dumps({"case": "broken"}), encoding="utf-8")

            returncode = materializer.main([
                str(manifest), "--output-root", str(Path(tmp) / "assets"), "--plan-only"
            ])

        self.assertEqual(returncode, 2)

    def test_declared_source_plan_builds_at_guard_checkout_root(self):
        manifest = {
            "case": "guide",
            "repository": "example/guide",
            "checkout_root": "/private/tmp/guide/complete",
            "git_revision": "a" * 40,
            "artifact_path": "target/app.jar",
            "artifact_sha256": "b" * 64,
            "materialization": {
                "kind": "source_build",
                "repository_url": "https://github.com/example/guide.git",
                "working_directory": "complete",
                "command": ["mvn", "package"],
                "artifact_path": "target/app.jar",
            },
        }

        plan = materializer.build_declared_materialization_plan(manifest)

        self.assertEqual(plan[0]["argv"][-1], "/private/tmp/guide")
        self.assertEqual(plan[2]["cwd"], "/private/tmp/guide/complete")
        self.assertEqual(plan[3]["path"], "/private/tmp/guide/complete/target/app.jar")
        self.assertEqual(plan[3]["sha256"], "b" * 64)

    def test_declared_published_plan_clones_source_and_downloads_exact_artifact(self):
        manifest = {
            "case": "published",
            "repository": "example/project",
            "checkout_root": "/private/tmp/project",
            "git_revision": "a" * 40,
            "artifact_path": "/private/tmp/project.jar",
            "materialization": {
                "kind": "published_artifact",
                "url": "https://repo.example/project.jar",
                "sha1": "b" * 40,
                "sha256": "c" * 64,
            },
        }

        plan = materializer.build_declared_materialization_plan(manifest)

        self.assertEqual(
            [step["operation"] for step in plan],
            ["git_clone", "command", "download", "verify"],
        )
        self.assertEqual(plan[0]["argv"][3], "https://github.com/example/project.git")
        self.assertEqual(plan[2]["destination"], "/private/tmp/project.jar")

    def test_guard_selector_matches_every_executable_guard_case(self):
        selected = materializer.select_guard_manifests()
        expected = sorted({
            Path(case.fixture_manifest)
            for case in materializer.CASES.values()
            if case.case_mode == "guard" and case.fixture_manifest is not None
        })

        self.assertEqual(selected, expected)
        self.assertGreater(len(selected), 1)

    def test_guard_selectors_partition_core_and_capability_manifests(self):
        core = set(materializer.select_guard_manifests("guard-core"))
        capability = set(materializer.select_guard_manifests("guard-capability"))
        aggregate = set(materializer.select_guard_manifests("guard"))

        self.assertTrue(core)
        self.assertTrue(capability)
        self.assertFalse(core & capability)
        self.assertEqual(core | capability, aggregate)


if __name__ == "__main__":
    unittest.main()
