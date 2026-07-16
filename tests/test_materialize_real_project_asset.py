import json
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
