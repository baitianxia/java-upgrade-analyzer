import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from execution_faults import (  # noqa: E402
    EXECUTION_FAULTS,
    run_execution_fault,
    run_production_stage_boundary_faults,
)


class ExecutionFaultTest(unittest.TestCase):
    def test_registry_covers_every_declared_execution_boundary(self):
        self.assertEqual(
            {spec.id for spec in EXECUTION_FAULTS},
            {
                "subprocess_timeout",
                "subprocess_nonzero_exit",
                "truncated_output",
                "partial_artifact_write",
                "artifact_replacement",
                "permission_denied",
                "invalid_encoding",
                "process_interruption",
                "process_cancellation",
                "cache_race",
            },
        )

    def test_every_fault_is_detected_with_exact_reason_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = [
                run_execution_fault(spec, Path(tmp) / spec.id)
                for spec in EXECUTION_FAULTS
            ]

        self.assertEqual(
            [(result.status, result.reason_code) for result in results],
            [("failed_closed", spec.expected_reason) for spec in EXECUTION_FAULTS],
        )
        self.assertTrue(all(result.before_sha256 for result in results))
        self.assertTrue(all(result.after_sha256 for result in results))
        self.assertTrue(all(result.cleanup_complete for result in results))

    def test_malformed_or_partial_output_never_becomes_empty_success(self):
        selected = [
            spec for spec in EXECUTION_FAULTS
            if spec.id in {"truncated_output", "partial_artifact_write", "invalid_encoding"}
        ]
        with tempfile.TemporaryDirectory() as tmp:
            results = [run_execution_fault(spec, Path(tmp) / spec.id) for spec in selected]

        self.assertTrue(all(result.status != "passed" for result in results))
        self.assertTrue(all(result.reason_code for result in results))

    def test_step1_step4_and_step5_production_boundaries_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = run_production_stage_boundary_faults(Path(tmp))

        self.assertEqual(
            {(result.stage, result.fault_id) for result in results},
            {
                ("step1", "corrupt_final_artifact"),
                ("step4", "truncated_japicmp_xml"),
                ("step5", "replaced_business_artifact"),
                ("step5", "corrupt_member_cache"),
            },
        )
        self.assertTrue(all(result.status == "failed_closed" for result in results))
        self.assertTrue(all(result.reason_code for result in results))
        self.assertTrue(all(result.production_entrypoint for result in results))


if __name__ == "__main__":
    unittest.main()
