import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "blackbox_runtime"
    / "real_project_public_contract_v1.json"
).read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class PublicRealProjectContractBlackboxTest(unittest.TestCase):
    def test_fixed_revision_exact_truth_and_release_execution_are_public(self):
        manifest_path = ROOT / TRUTH["manifest"]
        self.assertEqual(sha256(manifest_path), TRUTH["manifest_sha256"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["repository"], TRUTH["repository"])
        self.assertEqual(manifest["git_revision"], TRUTH["git_revision"])
        self.assertEqual(
            manifest["assets"]["application"]["sha256"],
            TRUTH["application_sha256"],
        )
        base = manifest["assets"]["base_dependency"]
        current = manifest["current_nested_asset"]
        self.assertEqual(base["sha256"], TRUTH["dependency_sha256"])
        self.assertEqual(current["sha256"], TRUTH["dependency_sha256"])
        self.assertEqual(base["coordinate"], current["coordinate"])
        expected = manifest["expected"]
        formal_truth = expected["formal_result_truth"]
        self.assertEqual(
            formal_truth["result_set_policy"],
            TRUTH["expected_result_set_policy"],
        )
        self.assertEqual(
            len(formal_truth["expected_results"]),
            TRUTH["expected_result_count"],
        )
        self.assertEqual(
            set(formal_truth["exact_reachability_statuses"]),
            {
                "reachable", "uncertain", "not_found_in_static_analysis",
                "not_analyzed",
            },
        )
        provenance = expected["oracle_provenance"]
        self.assertFalse(provenance["system_generated"])
        self.assertEqual(
            provenance["oracle_kind"], TRUTH["expected_oracle_kind"]
        )
        self.assertGreaterEqual(
            len(provenance["oracle_producers"]),
            TRUTH["minimum_oracle_producer_count"],
        )

        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "binary_real_project_guard.py"),
                "--manifest", str(manifest_path), "--verify-manifest",
            ],
            cwd=str(ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", check=False, timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        public = json.loads(completed.stdout)
        self.assertEqual(public["status"], "passed", public["issues"])
        self.assertEqual(public["manifest_sha256"], TRUTH["manifest_sha256"])
        self.assertEqual(public["expected_result_count"], 0)
        self.assertEqual(public["oracle_kind"], TRUTH["expected_oracle_kind"])
        self.assertGreaterEqual(
            public["oracle_producer_count"],
            TRUTH["minimum_oracle_producer_count"],
        )
        self.assertTrue(all(public["noop_preconditions"].values()))

        workflow = (
            ROOT / TRUTH["scheduled_release_workflow"]
        ).read_text(encoding="utf-8")
        self.assertIn("schedule:", workflow)
        self.assertIn("quality_gate.py --profile release", workflow)
        dry_run = subprocess.run(
            [
                sys.executable, str(ROOT / "scripts" / "quality_gate.py"),
                "--profile", "release", "--dry-run",
            ],
            cwd=str(ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", check=False, timeout=30,
        )
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        matching_commands = [
            line for line in dry_run.stdout.splitlines()
            if "binary_real_project_guard.py" in line
            and str(manifest_path) in line
        ]
        self.assertEqual(len(matching_commands), 1, dry_run.stdout)
        self.assertIn("--download", matching_commands[0])


if __name__ == "__main__":
    unittest.main()
