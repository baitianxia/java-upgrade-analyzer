import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

from tests.blackbox.harness import required_tools


ROOT = Path(__file__).resolve().parents[2]
TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "blackbox_runtime"
    / "performance_public_contract_v1.json"
).read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class PublicPerformanceContractBlackboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = required_tools()

    def test_public_smoke_conserves_independent_facts_with_time_and_rss_budgets(self):
        expected = TRUTH["smoke"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "result.json"
            started = time.monotonic()
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "binary_performance_gate.py"),
                    "--work-root", str(root / "work"),
                    "--output", str(output),
                    "--jar-count", str(expected["jar_count"]),
                    "--classes-per-jar", str(expected["classes_per_jar"]),
                    "--warm-samples", "2",
                    "--skip-legacy",
                ],
                cwd=str(ROOT), capture_output=True, text=True,
                encoding="utf-8", errors="replace", check=False, timeout=90,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])
            public = json.loads(output.read_text(encoding="utf-8"))
            summary = json.loads(completed.stdout)
            manifest = json.loads((
                root / "work" / "dataset" / "manifest.json"
            ).read_text(encoding="utf-8"))
            artifacts = [Path(item["path"]) for item in manifest["artifacts"]]

            independent_classes = []
            independent_hashes = []
            for artifact, row in zip(artifacts, manifest["artifacts"], strict=True):
                independent_hashes.append(sha256(artifact))
                self.assertEqual(independent_hashes[-1], row["sha256"])
                with zipfile.ZipFile(artifact) as archive:
                    independent_classes.extend(sorted(
                        name for name in archive.namelist()
                        if name.endswith(".class")
                    ))
            self.assertEqual(len(artifacts), expected["jar_count"])
            self.assertEqual(len(independent_classes), expected["class_count"])
            self.assertEqual(
                independent_hashes,
                public["measurement_protocol"]["dataset_artifact_identities"],
            )
            for class_index, class_entry in enumerate(independent_classes):
                owner = class_entry.removesuffix(".class").replace("/", ".")
                artifact = artifacts[class_index // expected["classes_per_jar"]]
                javap = subprocess.run(
                    [self.tools["javap"], "-classpath", str(artifact), "-c", "-s", "-p", owner],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", check=False, timeout=30,
                )
                self.assertEqual(javap.returncode, 0, javap.stderr)
                self.assertIn("public int value();", javap.stdout)
                self.assertIn("public java.lang.String text();", javap.stdout)

            protocol = public["measurement_protocol"]
            cold = public["measurements"]["cold"]
            full = public["measurements"]["full_pipeline_probe"]
            changed = public["measurements"]["changed_full_pipeline_probe"]
            self.assertEqual(public["status"], "measured")
            self.assertEqual(summary["status"], "measured")
            self.assertEqual(protocol["jar_count"], expected["jar_count"])
            self.assertEqual(protocol["class_count"], expected["class_count"])
            self.assertEqual(cold["counts"], {
                "entries": expected["class_count"],
                "classes": expected["class_count"],
                "members": expected["member_count"],
                "edges": expected["edge_count"],
                "resources": 0,
            })
            self.assertEqual(cold["parser_invocations"], expected["jar_count"])
            for warm in public["measurements"]["warm_runs"]:
                self.assertEqual(warm["parser_invocations"], 0)
                self.assertEqual(warm["cache_hits"], expected["jar_count"])
                self.assertEqual(warm["counts"], cold["counts"])
            self.assertEqual(full["validation_status"], "passed")
            self.assertEqual(full["validation_issue_count"], 0)
            self.assertEqual(full["base_class_count"], expected["class_count"])
            self.assertEqual(full["current_class_count"], expected["class_count"])
            self.assertEqual(full["authoritative_change_fact_count"], 0)
            self.assertEqual(full["formal_api_result_count"], 0)
            self.assertEqual(changed["validation_status"], "passed")
            self.assertEqual(changed["validation_issue_count"], 0)
            self.assertEqual(changed["base_class_count"], expected["class_count"])
            self.assertEqual(changed["current_class_count"], expected["class_count"])
            self.assertEqual(
                changed["authoritative_change_fact_count"],
                expected["authoritative_change_fact_count"],
            )
            self.assertEqual(
                changed["formal_api_result_count"], expected["formal_api_result_count"]
            )
            self.assertEqual(
                changed["authoritative_member_change_kind_counts"],
                {"implementation_changed": expected["changed_class_count"]},
            )

            self.assertLessEqual(elapsed, expected["external_elapsed_seconds_max"])
            self.assertLessEqual(cold["end_to_end_seconds"], expected["cold_seconds_max"])
            self.assertLessEqual(
                public["measurements"]["warm_end_to_end_p50_seconds"],
                expected["warm_p50_seconds_max"],
            )
            self.assertLessEqual(
                public["measurements"]["warm_end_to_end_p95_seconds"],
                expected["warm_p95_seconds_max"],
            )
            self.assertLessEqual(
                full["end_to_end_seconds"], expected["full_pipeline_seconds_max"]
            )
            self.assertLessEqual(
                changed["end_to_end_seconds"],
                expected["changed_full_pipeline_seconds_max"],
            )
            self.assertLessEqual(
                public["measurements"]["peak_rss_bytes"],
                expected["peak_rss_bytes_max"],
            )
            measured_runs = [
                cold,
                *public["measurements"]["warm_runs"],
                full,
                changed,
            ]
            for measured in measured_runs:
                self.assertGreaterEqual(measured["cpu_seconds"], 0)
                self.assertGreaterEqual(measured["average_cpu_cores"], 0)
            self.assertGreater(
                public["measurements"]["total_measured_cpu_seconds"], 0
            )
            self.assertGreater(public["measurements"]["average_cpu_cores"], 0)

    def test_release_scale_evidence_is_replayed_and_scheduled_publicly(self):
        expected = TRUTH["release_scale"]
        gate_path = (
            ROOT / "tests" / "fixtures" / "binary_first"
            / "performance_gate.json"
        )
        self.assertEqual(sha256(gate_path), expected["recorded_gate_sha256"])
        gate = json.loads(gate_path.read_text(encoding="utf-8"))
        protocol = gate["measurement_protocol"]
        recorded = gate["recorded_measurements"]
        self.assertEqual(protocol["jar_count"], expected["jar_count"])
        self.assertEqual(
            protocol["classes_per_jar"], expected["classes_per_jar"]
        )
        self.assertEqual(protocol["class_count"], expected["class_count"])
        self.assertEqual(
            protocol["jar_count"] * protocol["classes_per_jar"],
            protocol["class_count"],
        )
        self.assertEqual(
            protocol["changed_full_pipeline_probe"]["changed_jar_count"],
            expected["changed_jar_count"],
        )
        self.assertEqual(
            protocol["changed_full_pipeline_probe"]["changed_class_count"],
            expected["changed_class_count"],
        )
        self.assertEqual(recorded["class_count"], expected["class_count"])
        self.assertEqual(
            recorded["warm_end_to_end_p50_seconds"],
            sorted(recorded["warm_end_to_end_samples_seconds"])[1],
        )
        self.assertEqual(
            recorded["cpu_measurement_status"],
            "recorded",
        )
        self.assertEqual(
            protocol["cpu_time_source"],
            "resource.getrusage(self+completed_children)",
        )
        cpu_runs = [
            (
                recorded["cold_end_to_end_seconds"],
                recorded["cold_cpu_seconds"],
                recorded["cold_average_cpu_cores"],
            ),
            *zip(
                recorded["warm_end_to_end_samples_seconds"],
                recorded["warm_cpu_seconds_samples"],
                recorded["warm_average_cpu_cores_samples"],
                strict=True,
            ),
            (
                recorded["legacy_end_to_end_seconds"],
                recorded["legacy_cpu_seconds"],
                recorded["legacy_average_cpu_cores"],
            ),
            *[
                (
                    recorded[name]["end_to_end_seconds"],
                    recorded[name]["cpu_seconds"],
                    recorded[name]["average_cpu_cores"],
                )
                for name in (
                    "full_pipeline_probe", "changed_full_pipeline_probe"
                )
            ],
        ]
        for wall, cpu, average in cpu_runs:
            self.assertAlmostEqual(average, cpu / wall, places=9)
        self.assertAlmostEqual(
            recorded["total_measured_wall_seconds"],
            sum(item[0] for item in cpu_runs),
            places=9,
        )
        self.assertAlmostEqual(
            recorded["total_measured_cpu_seconds"],
            sum(item[1] for item in cpu_runs),
            places=9,
        )
        self.assertEqual(
            recorded["full_pipeline_probe"]["base_class_count"],
            expected["class_count"],
        )
        self.assertEqual(
            recorded["full_pipeline_probe"]["current_class_count"],
            expected["class_count"],
        )
        self.assertEqual(
            recorded["changed_full_pipeline_probe"]["base_class_count"],
            expected["class_count"],
        )
        self.assertEqual(
            recorded["changed_full_pipeline_probe"]["current_class_count"],
            expected["class_count"],
        )

        verified = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "binary_performance_gate.py"),
                "--verify-recorded-gate", str(gate_path),
            ],
            cwd=str(ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", check=False, timeout=30,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        verification = json.loads(verified.stdout)
        self.assertEqual(verification["status"], "passed", verification["issues"])
        self.assertEqual(verification["issue_count"], 0)
        self.assertTrue(verification["recorded_measurements_replayed"])

        workflow = (
            ROOT / expected["scheduled_release_workflow"]
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
        self.assertIn("binary_performance_gate.py", dry_run.stdout)
        self.assertIn("--gate", dry_run.stdout)
        self.assertIn(str(gate_path), dry_run.stdout)


if __name__ == "__main__":
    unittest.main()
