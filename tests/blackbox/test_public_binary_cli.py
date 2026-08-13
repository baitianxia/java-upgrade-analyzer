import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from tests.blackbox.harness import (
    compare_truth_with_oracle,
    compile_fixture,
    evaluate_closed_truth,
    package_variant,
    pipeline_config,
    required_tools,
    run_public_pipeline,
    semantic_projection,
    sha256,
)
from tests.blackbox.oracles.openjdk_oracle import evaluate_fixture
from tests.blackbox.oracles.openjdk_class_oracle import final_class_transition


ROOT = Path(__file__).resolve().parents[2]
CASE_ROOTS = sorted(
    path.parent
    for path in (ROOT / "tests" / "fixtures" / "blackbox").glob("*/case.json")
)
CACHE_TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "blackbox_runtime"
    / "cache_public_contract_v1.json"
).read_text(encoding="utf-8"))
ATOMIC_TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "blackbox_runtime"
    / "atomic_publication_v1.json"
).read_text(encoding="utf-8"))


class PublicBinaryCliBlackboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls.temporary.name)
        cls.tools = required_tools()
        cls.fixtures = []
        for case_root in CASE_ROOTS:
            case = json.loads((case_root / "case.json").read_text(encoding="utf-8"))
            truth = json.loads((case_root / "truth.json").read_text(encoding="utf-8"))
            case_workspace = cls.workspace / str(case["case_id"])
            compiled = compile_fixture(case_root, case_workspace, cls.tools)
            cls.fixtures.append({
                "case": case,
                "truth": truth,
                "workspace": case_workspace,
                "baseline": package_variant(
                    compiled, case_workspace, variant="baseline"
                ),
                "repacked": package_variant(
                    compiled, case_workspace, variant="repacked"
                ),
            })

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_openjdk_oracles_confirm_the_complete_authored_truth(self):
        for fixture in self.fixtures:
            with self.subTest(case=fixture["case"]["case_id"]):
                oracle = evaluate_fixture(
                    case=fixture["case"],
                    base_library=fixture["baseline"]["base"],
                    current_library=fixture["baseline"]["current"],
                    business_jar=fixture["baseline"]["business"],
                    oracle_jar=fixture["baseline"]["oracle"],
                    java=self.tools["java"],
                    javap=self.tools["javap"],
                )

                self.assertEqual(
                    compare_truth_with_oracle(fixture["truth"], oracle), (), oracle
                )
                if fixture["case"].get("case_id") == "final-class-change-v1":
                    class_observation = final_class_transition(
                        javap=self.tools["javap"],
                        base_jar=fixture["baseline"]["base"],
                        current_jar=fixture["baseline"]["current"],
                        class_name=fixture["case"]["library_class"],
                    )
                    expected_class_identities = {
                        (
                            row["owner"], row["member"], row["descriptor"],
                            row["member_kind"],
                        )
                        for row in fixture["truth"]["expected_results"]
                        if row["member_kind"] == "class"
                    }
                    self.assertEqual(
                        expected_class_identities,
                        {class_observation["identity"]},
                        class_observation,
                    )
                    self.assertEqual(class_observation["added_flags"], ("ACC_FINAL",))
                    self.assertEqual(class_observation["removed_flags"], ())
                self.assertNotEqual(
                    sha256(fixture["baseline"]["base"]),
                    sha256(fixture["repacked"]["base"]),
                )
                self.assertNotEqual(
                    sha256(fixture["baseline"]["business"]),
                    sha256(fixture["repacked"]["business"]),
                )

    def test_public_cli_matches_closed_truth_and_ignores_packaging_noise(self):
        for fixture in self.fixtures:
            projections = []
            for variant, artifacts in (
                ("baseline", fixture["baseline"]),
                ("repacked", fixture["repacked"]),
            ):
                with self.subTest(
                    case=fixture["case"]["case_id"], variant=variant
                ):
                    _result, formal = run_public_pipeline(
                        ROOT, fixture["case"], artifacts, fixture["workspace"],
                        java=self.tools["java"],
                    )
                    evaluation = evaluate_closed_truth(formal, fixture["truth"])
                    self.assertEqual(
                        evaluation["status"], "passed", evaluation["issues"]
                    )
                    self.assertEqual(
                        evaluation["metrics"]["false_positive_count"], 0
                    )
                    self.assertEqual(
                        evaluation["metrics"]["false_negative_count"], 0
                    )
                    self.assertEqual(
                        evaluation["metrics"]["state_mismatch_count"], 0
                    )
                    self.assertEqual(
                        evaluation["metrics"]["path_mismatch_count"], 0
                    )
                    self.assertEqual(
                        evaluation["metrics"]["forbidden_hit_count"], 0
                    )
                    projections.append(semantic_projection(formal))

            if len(projections) == 2:
                self.assertEqual(projections[0], projections[1])

    def test_cache_repeat_corruption_and_concurrent_runs_are_deterministic(self):
        truth = CACHE_TRUTH
        fixture = self.fixtures[0]
        workspace = fixture["workspace"] / "cache-public-contract"
        artifacts = fixture["baseline"]
        first, first_formal = run_public_pipeline(
            ROOT, fixture["case"], artifacts, workspace,
            java=self.tools["java"],
        )
        self.assertEqual(
            first["validation_status"], truth["expected_validation_status"]
        )
        self.assertGreater(first["cache_metrics"]["artifact_snapshot_misses"], 0)
        self.assertGreater(first["cache_metrics"]["classfile_parser_invocations"], 0)
        first_cache_status = (
            "miss"
            if (
                first["cache_metrics"]["artifact_snapshot_misses"] > 0
                and first["cache_metrics"]["classfile_parser_invocations"] > 0
            )
            else "unexpected"
        )
        self.assertEqual(first_cache_status, truth["expected_first_status"])

        warm, warm_formal = run_public_pipeline(
            ROOT, fixture["case"], artifacts, workspace,
            java=self.tools["java"],
        )
        self.assertEqual(
            warm["result_generation_identity"], first["result_generation_identity"]
        )
        self.assertEqual(warm["cache_metrics"]["artifact_snapshot_misses"], 0)
        self.assertGreater(warm["cache_metrics"]["artifact_snapshot_disk_hits"], 0)
        self.assertEqual(warm["cache_metrics"]["classfile_parser_invocations"], 0)
        warm_cache_status = (
            "hit"
            if (
                warm["cache_metrics"]["artifact_snapshot_misses"] == 0
                and warm["cache_metrics"]["artifact_snapshot_disk_hits"] > 0
                and warm["cache_metrics"]["classfile_parser_invocations"] == 0
            )
            else "unexpected"
        )
        self.assertEqual(warm_cache_status, truth["expected_warm_status"])
        self.assertEqual(
            semantic_projection(warm_formal), semantic_projection(first_formal)
        )

        cache_root = workspace / "runs" / "baseline" / "output" / "binary_cache"
        cache_files = sorted(cache_root.rglob("*.json.zlib"))
        self.assertTrue(cache_files)
        cache_files[0].write_bytes(b"independently-corrupted-cache-entry")
        rebuilt, rebuilt_formal = run_public_pipeline(
            ROOT, fixture["case"], artifacts, workspace,
            java=self.tools["java"],
        )
        self.assertEqual(
            rebuilt["result_generation_identity"], first["result_generation_identity"]
        )
        self.assertEqual(
            rebuilt["cache_metrics"]["artifact_snapshot_corrupt_rebuilt"], 1
        )
        self.assertGreaterEqual(
            rebuilt["cache_metrics"]["classfile_parser_invocations"], 1
        )
        rebuilt_cache_status = (
            "corrupt_rebuilt"
            if (
                rebuilt["cache_metrics"]["artifact_snapshot_corrupt_rebuilt"] == 1
                and rebuilt["cache_metrics"]["classfile_parser_invocations"] >= 1
            )
            else "unexpected"
        )
        self.assertEqual(rebuilt_cache_status, truth["expected_corrupt_status"])
        self.assertEqual(
            semantic_projection(rebuilt_formal), semantic_projection(first_formal)
        )

        concurrent = workspace / "concurrent"
        concurrent.mkdir(parents=True)
        config_path = concurrent / "config.json"
        config_path.write_text(
            json.dumps(pipeline_config(
                fixture["case"], artifacts, java=self.tools["java"]
            )),
            encoding="utf-8",
        )
        output_root = concurrent / "output"
        command_prefix = [
            sys.executable, str(ROOT / "scripts" / "binary_pipeline.py"),
            "--config", str(config_path), "--output-root", str(output_root),
        ]
        processes = [
            subprocess.Popen(
                [*command_prefix, "--result-json", str(concurrent / f"result-{index}.json")],
                cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace",
            )
            for index in range(2)
        ]
        observations = [
            (process, *process.communicate(timeout=180)) for process in processes
        ]
        failures = [
            (process.returncode, stdout[-2000:], stderr[-4000:])
            for process, stdout, stderr in observations
            if process.returncode != 0
        ]
        self.assertEqual(failures, [])
        concurrent_results = [
            json.loads(stdout) for _process, stdout, _stderr in observations
        ]
        self.assertEqual(
            {row["validation_status"] for row in concurrent_results},
            {truth["expected_validation_status"]},
        )
        identities = {
            row["result_generation_identity"] for row in concurrent_results
        }
        self.assertEqual(
            len(identities), truth["expected_concurrent_result_identity_count"]
        )
        active = json.loads((
            output_root / "active_binary_generation.json"
        ).read_text(encoding="utf-8"))
        self.assertIn(active["result_generation_identity"], identities)

    def test_interrupted_generation_never_moves_the_active_pointer(self):
        truth = ATOMIC_TRUTH
        fixture = self.fixtures[0]
        workspace = fixture["workspace"] / "atomic-public-contract"
        baseline, _formal = run_public_pipeline(
            ROOT, fixture["case"], fixture["baseline"], workspace,
            java=self.tools["java"],
        )
        output_root = workspace / "runs" / "baseline" / "output"
        active_path = output_root / "active_binary_generation.json"
        active_before = active_path.read_bytes()
        baseline_generation = Path(baseline["generation_directory"])

        def generation_bytes(directory: Path) -> dict[str, str]:
            return {
                path.relative_to(directory).as_posix(): sha256(path)
                for path in sorted(directory.rglob("*")) if path.is_file()
            }

        baseline_bytes = generation_bytes(baseline_generation)
        known_generations = {
            path.name for path in (output_root / "binary_generations").iterdir()
            if path.is_dir() and len(path.name) == 64
        }
        config_path = workspace / "interrupt-config.json"
        result_path = workspace / "interrupt-result.json"
        config_path.write_text(
            json.dumps(pipeline_config(
                fixture["case"], fixture["repacked"], java=self.tools["java"]
            )),
            encoding="utf-8",
        )
        command = [
            sys.executable, str(ROOT / "scripts" / "binary_pipeline.py"),
            "--config", str(config_path), "--output-root", str(output_root),
            "--result-json", str(result_path),
        ]
        process = subprocess.Popen(
            command, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
        )
        interrupted = False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and process.poll() is None:
            generations = {
                path.name
                for path in (output_root / "binary_generations").iterdir()
                if path.is_dir() and len(path.name) == 64
            }
            if generations - known_generations:
                process.kill()
                interrupted = True
                break
            time.sleep(0.005)
        stdout, stderr = process.communicate(timeout=30)
        self.assertTrue(
            interrupted,
            ("process completed before fault injection", process.returncode, stdout, stderr),
        )
        self.assertNotEqual(process.returncode, 0)
        prior_pointer_changed = active_path.read_bytes() != active_before
        self.assertEqual(
            prior_pointer_changed,
            truth["expected_prior_pointer_change_after_interruption"],
            "interrupted unvalidated generation became active",
        )
        current_baseline_bytes = generation_bytes(baseline_generation)
        prior_generation_change_count = sum(
            baseline_bytes.get(relative) != current_baseline_bytes.get(relative)
            for relative in baseline_bytes.keys() | current_baseline_bytes.keys()
        )
        self.assertEqual(
            prior_generation_change_count,
            truth["expected_prior_generation_byte_change_count"],
            "interruption mutated the prior immutable generation",
        )

        retried = subprocess.run(
            command, cwd=str(ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", check=False, timeout=180,
        )
        self.assertEqual(retried.returncode, 0, retried.stderr[-4000:])
        retry_result = json.loads(retried.stdout)
        self.assertEqual(
            retry_result["validation_status"],
            truth["expected_retry_validation_status"],
        )
        active_after = json.loads(active_path.read_text(encoding="utf-8"))
        self.assertEqual(
            active_after["result_generation_identity"],
            retry_result["result_generation_identity"],
        )
        self.assertNotEqual(active_path.read_bytes(), active_before)


if __name__ == "__main__":
    unittest.main()
