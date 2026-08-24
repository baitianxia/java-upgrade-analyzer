from contextlib import nullcontext, redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_performance_gate  # noqa: E402
from binary_performance_identity import HARNESS_SOURCE_PATHS  # noqa: E402
from binary_performance_gate import (  # noqa: E402
    evaluate_gate,
    evaluate_recorded_gate,
    run_benchmark,
)


class PerformanceProcessMetricsTest(unittest.TestCase):
    def test_windows_fallback_uses_native_cpu_and_peak_memory(self):
        usage = SimpleNamespace(
            user_seconds=1.25,
            system_seconds=0.5,
            peak_rss_bytes=16 * 1024 * 1024,
        )
        with patch.object(binary_performance_gate, "_resource", None), patch.object(
            binary_performance_gate,
            "windows_current_process_usage",
            return_value=usage,
        ):
            cpu_seconds = binary_performance_gate._cpu_seconds()
            peak_rss_bytes = binary_performance_gate._rss_bytes()

        self.assertEqual(cpu_seconds, 1.75)
        self.assertEqual(peak_rss_bytes, 16 * 1024 * 1024)

    def test_performance_source_closure_includes_measured_support_code(self):
        self.assertIn("process_lock.py", HARNESS_SOURCE_PATHS)
        self.assertIn("progress_logging.py", HARNESS_SOURCE_PATHS)


class BinaryPerformanceGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("java") or not shutil.which("javac"):
            raise unittest.SkipTest("full JDK required")
        try:
            binary_asm_helper.resolve_asm_jar()
        except Exception as error:
            raise unittest.SkipTest(str(error)) from error

    def _currentized_recorded_gate(self):
        """Upgrade the historical numeric fixture to the current protocol.

        This keeps unit tests independent of the multi-hour 400x250 capture:
        the already-recorded measurements remain unchanged while deterministic
        source and logical dataset bindings are reconstructed locally.
        """

        gate = json.loads((
            ROOT_DIR / "tests" / "fixtures" / "binary_first"
            / "performance_gate.json"
        ).read_text(encoding="utf-8"))
        policy = binary_performance_gate.release_policy()
        protocol = gate["measurement_protocol"]
        protocol.update(json.loads(json.dumps(policy["measurement_protocol"])))
        protocol.pop("artifact_identity_set_binding", None)
        protocol["release_policy_identity"] = (
            binary_performance_gate.release_policy_identity()
        )
        reference_runtime = json.loads(json.dumps(policy["reference_runtime"]))
        protocol["reference_runtime"] = reference_runtime
        for field in (
            "machine_identity", "machine", "tool_versions",
            "cpu_time_source", "peak_rss_source",
        ):
            protocol[field] = json.loads(json.dumps(reference_runtime[field]))
        cached = getattr(type(self), "_recorded_policy_dataset", None)
        if cached is None:
            dataset_temp = tempfile.TemporaryDirectory()
            type(self)._recorded_policy_dataset_temp = dataset_temp
            self.addClassCleanup(dataset_temp.cleanup)
            artifacts = binary_performance_gate.build_dataset(
                Path(dataset_temp.name), jar_count=400, classes_per_jar=250
            )
            changed = binary_performance_gate.build_changed_current_artifacts(
                Path(dataset_temp.name), artifacts, classes_per_jar=250
            )
            cached = (artifacts, changed)
            type(self)._recorded_policy_dataset = cached
        artifacts, changed = cached
        artifact_identities = [item["sha256"] for item in artifacts]
        protocol["dataset_artifact_identities"] = artifact_identities
        protocol["first_base_artifact_identity"] = artifact_identities[0]
        current = (
            binary_performance_gate._performance_implementation_protocol(
                include_runtime=False
            )
        )
        implementation = {
            **current,
            "pipeline_generation_implementation_identity": policy[
                "reference_implementation"
            ]["pipeline_generation_implementation_identity"],
            "validator_implementation_identity": policy[
                "reference_implementation"
            ]["validator_implementation_identity"],
            "jdk_preflight_identity": reference_runtime[
                "jdk_preflight_identity"
            ],
        }
        implementation["runtime_implementation_identity"] = (
            binary_performance_gate._runtime_implementation_identity(
                implementation
            )
        )
        protocol["implementation"] = implementation
        protocol["source_implementation_identity"] = current[
            "source_implementation_identity"
        ]
        protocol["runtime_implementation_identity"] = implementation[
            "runtime_implementation_identity"
        ]
        changed_identity = changed[0]["sha256"]
        changed_probe = protocol["changed_full_pipeline_probe"]
        changed_probe["current_artifact_identity"] = changed_identity
        changed_probe["logical_artifact_derivation_identity"] = (
            binary_performance_gate._changed_artifact_derivation_identity(
                base_artifact_identity=artifact_identities[0],
                current_artifact_identity=changed_identity,
                classes_per_jar=250,
            )
        )
        gate["thresholds"] = json.loads(json.dumps(policy["thresholds"]))
        gate["accuracy_invariants"] = json.loads(json.dumps(
            policy["accuracy_invariants"]
        ))
        recorded = gate["recorded_measurements"]
        captured_at = "2026-08-13T00:00:00Z"
        recorded["captured_at"] = captured_at
        cold_peak = recorded["cold_peak_rss_bytes"]
        recorded.update({
            "warmup_end_to_end_seconds": recorded[
                "cold_end_to_end_seconds"
            ],
            "warmup_cpu_seconds": recorded["cold_cpu_seconds"],
            "warmup_average_cpu_cores": recorded[
                "cold_average_cpu_cores"
            ],
            "warmup_parser_invocations": 400,
            "warmup_cache_hits": 0,
            "warmup_peak_rss_bytes": cold_peak,
            "warmup_class_count": 100_000,
        })
        recorded["warm_peak_rss_bytes_samples"] = [cold_peak] * 3
        recorded["legacy_peak_rss_bytes"] = cold_peak
        recorded["warm_parser_invocations_samples"] = [0] * 3
        recorded["warm_cache_hits_samples"] = [400] * 3
        recorded["cold_stage_seconds"] = {
            "inventory": recorded["stage_seconds"]["cold_inventory"],
            "parse_and_cache": recorded["stage_seconds"][
                "cold_parse_and_cache"
            ],
            "db_write_and_index": recorded["stage_seconds"][
                "cold_db_write_and_index"
            ],
            "overlay": 0.0,
            "batch_query_10000": recorded["stage_seconds"][
                "cold_batch_query_10000"
            ],
            "report_10000": recorded["stage_seconds"][
                "cold_report_10000"
            ],
        }
        authority_binding = {
            "schema": (
                "java-upgrade-analyzer.performance-authority-binding.v2"
            ),
            "authority_mode": "release_recapture_measurement",
            "support_contract_identity": "3" * 64,
            "evidence_sha256": "4" * 64,
            "source_implementation_identity": current[
                "source_implementation_identity"
            ],
        }
        authority_binding["binding_identity"] = (
            binary_performance_gate.canonical_identity(
                "binary_performance_authority_binding_identity",
                {
                    "support_contract_identity": authority_binding[
                        "support_contract_identity"
                    ],
                    "evidence_sha256": authority_binding[
                        "evidence_sha256"
                    ],
                    "source_implementation_identity": authority_binding[
                        "source_implementation_identity"
                    ],
                    "authority_mode": authority_binding["authority_mode"],
                },
                schema_version="1",
            )
        )
        for index, probe_name in enumerate((
            "full_pipeline_probe", "changed_full_pipeline_probe",
        ), start=1):
            probe = recorded[probe_name]
            probe.update({
                "status": "passed",
                "performance_authority_mode": (
                    "release_recapture_measurement"
                ),
                "process_id": 10_000 + index,
                "rss_measurement_scope": (
                    "dedicated_probe_process_and_completed_children"
                ),
                "artifact_snapshot_disk_hits": probe[
                    "artifact_snapshot_hits"
                ],
                "artifact_snapshot_memory_hits": 0,
                "pipeline_reported_seconds": probe[
                    "end_to_end_seconds"
                ],
                "pipeline_total_elapsed_scope": (
                    "current_pipeline_attempt"
                ),
                "pipeline_phase_timings_scope": (
                    "current_pipeline_attempt"
                ),
                "pipeline_reported_peak_rss_bytes": probe[
                    "peak_rss_bytes"
                ],
                "post_pipeline_peak_rss_bytes": probe[
                    "peak_rss_bytes"
                ],
                "pipeline_performance_authority_binding": dict(
                    authority_binding
                ),
                "activation_authority_mode": (
                    "release_recapture_measurement"
                ),
                "publication_deferred": False,
                "checkpoint_retained": False,
                "activation_candidate_discarded": False,
                "activation_recapture_discarded": True,
                "active_generation_absent": True,
                "pending_generation_absent": True,
                "validation_checkpoint_absent": True,
                "captured_at": captured_at,
            })
            first_peak = next(iter(probe["phase_peak_rss_bytes"].values()))
            probe["phase_seconds"] = {
                "static_preflight": 0.001,
                **probe["phase_seconds"],
            }
            probe["phase_peak_rss_bytes"] = {
                "static_preflight": first_peak,
                **probe["phase_peak_rss_bytes"],
            }
        return gate

    def test_recorded_and_provisional_replay_resolve_live_implementation(self):
        recorded = binary_performance_gate._evaluate_recorded_gate(
            {},
            current_source_implementation=None,
            require_live_runtime_implementation=True,
        )
        self.assertEqual(recorded["status"], "failed")

        protocol = {
            "implementation": {},
            "source_implementation_identity": "a" * 64,
            "runtime_implementation_identity": "b" * 64,
            "dataset_identity": "c" * 64,
        }
        provisional = binary_performance_gate.evaluate_provisional_gate({
            "measurement_protocol": protocol,
            "measurement_provisional": {
                "schema": (
                    "java-upgrade-analyzer.binary-performance-provisional.v1"
                ),
                "purpose": "isolated_release_path_recapture_only",
                "source_implementation_identity": "a" * 64,
                "runtime_implementation_identity": "b" * 64,
                "dataset_identity": "c" * 64,
                "candidate_probe_authority_mode": (
                    binary_performance_gate._CANDIDATE_PROBE_AUTHORITY_MODE
                ),
                "candidate_result_sha256": "d" * 64,
                "public_activation_allowed": False,
            },
        })
        malformed = binary_performance_gate.evaluate_provisional_gate([])

        self.assertEqual(provisional["status"], "failed")
        self.assertTrue(provisional["provisional_recapture_only"])
        self.assertEqual(malformed["status"], "failed")
        self.assertEqual(
            malformed["issues"][0]["reason_code"],
            "BINARY_PERFORMANCE_PROVISIONAL_ROOT_INVALID",
        )

    def test_completed_benchmark_recovery_handles_encoding_and_fallback_file(self):
        cyclic = {}
        cyclic["self"] = cyclic
        encoding = binary_performance_gate._persist_completed_benchmark_recovery(
            Path("/unused"), cyclic,
        )
        self.assertIn("result_encoding_error", encoding)

        with tempfile.TemporaryDirectory() as temporary, patch(
            "binary_pipeline._write_non_authoritative_json",
            return_value=False,
        ):
            receipt = (
                binary_performance_gate._persist_completed_benchmark_recovery(
                    Path(temporary), {"status": "passed", "value": 1},
                )
            )
            recovery_path = Path(receipt["recovery_path"])
            try:
                self.assertTrue(receipt["recovery_is_temporary"])
                self.assertEqual(
                    json.loads(recovery_path.read_text(encoding="utf-8")),
                    {"status": "passed", "value": 1},
                )
            finally:
                recovery_path.unlink(missing_ok=True)

    def test_probe_artifact_verifier_rejects_non_regular_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "artifact.jar"
            directory.mkdir()
            with self.assertRaises(
                binary_performance_gate.PerformanceGateError,
            ) as raised:
                binary_performance_gate._verify_probe_worker_artifact_file(
                    directory,
                    expected_size=0,
                    expected_sha256=hashlib.sha256(b"").hexdigest(),
                    field="artifacts[0]",
                )

        self.assertEqual(
            raised.exception.failure["reason_code"],
            "BINARY_PERFORMANCE_PROBE_INPUT_INVALID",
        )

    def test_cli_uses_real_recorded_verifier_and_bounds_structured_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gate = root / "recorded.json"
            verification = root / "verification.json"
            gate.write_text("{}\n", encoding="utf-8")
            verify_code = self._run_performance_cli([
                "--verify-recorded-gate", str(gate),
                "--output", str(verification),
            ])
            self.assertEqual(verify_code, 1)
            self.assertEqual(
                json.loads(verification.read_text(encoding="utf-8"))["status"],
                "failed",
            )

            output = root / "failure.json"
            failure = binary_performance_gate.PerformanceGateError(
                "benchmark rejected",
                failure={
                    "reason_code": "SYNTHETIC_BENCHMARK_REJECTED",
                    "detail": "x" * 20_000,
                },
            )
            with patch.object(
                binary_performance_gate, "run_benchmark", side_effect=failure,
            ):
                benchmark_code = self._run_performance_cli([
                    "--output", str(output),
                    "--jar-count", "1",
                    "--classes-per-jar", "1",
                    "--warm-samples", "1",
                    "--skip-legacy",
                ])

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(benchmark_code, 1)
            self.assertEqual(
                payload["failure"]["reason_code"],
                "SYNTHETIC_BENCHMARK_REJECTED",
            )
            self.assertTrue(payload["failure"]["detail"].endswith("...[truncated]"))

    def test_release_capture_rejects_mismatched_live_implementation_early(self):
        reference_runtime = {"runtime": "synthetic"}
        implementation = {
            "pipeline_generation_implementation_identity": "a" * 64,
            "validator_implementation_identity": "b" * 64,
        }
        policy = {
            "reference_runtime": reference_runtime,
            "reference_implementation": {
                "pipeline_generation_implementation_identity": "c" * 64,
                "validator_implementation_identity": "d" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            binary_performance_gate,
            "_performance_implementation_protocol",
            return_value=implementation,
        ), patch.object(
            binary_performance_gate,
            "_reference_runtime_protocol",
            return_value=reference_runtime,
        ), patch.object(
            binary_performance_gate, "release_policy", return_value=policy,
        ), self.assertRaises(
            binary_performance_gate.PerformanceGateError,
        ) as raised:
            binary_performance_gate.run_benchmark(
                Path(temporary),
                jar_count=400,
                classes_per_jar=250,
                warm_samples=3,
                include_legacy=True,
            )

        self.assertEqual(
            raised.exception.failure["reason_code"],
            "BINARY_PERFORMANCE_REFERENCE_IMPLEMENTATION_MISMATCH",
        )

    def _synthetic_builder_raw_result(
        self,
        *,
        authority_mode="candidate_source_measurement",
        evidence_sha256="9" * 64,
    ):
        """Create strict release-scale raw bytes without running the pipeline."""

        gate = self._currentized_recorded_gate()
        recorded = gate["recorded_measurements"]
        implementation = (
            binary_performance_gate._performance_implementation_protocol(
                binary_asm_helper.resolve_asm_jar()
            )
        )
        policy = deepcopy(binary_performance_gate.release_policy())
        policy["reference_implementation"] = {
            "schema": (
                "java-upgrade-analyzer."
                "binary-performance-reference-implementation.v1"
            ),
            "pipeline_generation_implementation_identity": implementation[
                "pipeline_generation_implementation_identity"
            ],
            "validator_implementation_identity": implementation[
                "validator_implementation_identity"
            ],
        }
        policy["reference_runtime"]["jdk_preflight_identity"] = implementation[
            "jdk_preflight_identity"
        ]
        policy_identity = "f" * 64
        protocol = deepcopy(gate["measurement_protocol"])
        protocol["release_policy_identity"] = policy_identity
        protocol["reference_runtime"] = deepcopy(policy["reference_runtime"])
        for field in (
            "machine_identity", "machine", "tool_versions",
            "cpu_time_source", "peak_rss_source",
        ):
            protocol[field] = deepcopy(policy["reference_runtime"][field])
        protocol["implementation"] = dict(implementation)
        protocol["source_implementation_identity"] = implementation[
            "source_implementation_identity"
        ]
        protocol["runtime_implementation_identity"] = implementation[
            "runtime_implementation_identity"
        ]

        counts = {
            "entries": 100_000,
            "classes": 100_000,
            "members": 300_000,
            "edges": 400_000,
            "resources": 0,
        }
        inventory = {
            "entry_count": 100_000,
            "uncompressed_bytes": 10_000_000,
        }

        def analysis_run(
            *, wall, cpu, parser, hits, peak, stages,
        ):
            db_bytes = int(recorded["sqlite_bytes"])
            cache_bytes = int(recorded["cache_bytes"])
            return {
                "end_to_end_seconds": float(wall),
                "cpu_seconds": float(cpu),
                "average_cpu_cores": float(cpu) / float(wall),
                "stage_seconds": deepcopy(stages),
                "parser_invocations": int(parser),
                "cache_hits": int(hits),
                "counts": dict(counts),
                "inventory": dict(inventory),
                "overlay_status": "not_provided",
                "report_bytes": 1,
                "db_bytes": db_bytes,
                "cache_bytes": cache_bytes,
                "peak_rss_bytes": int(peak),
                "bytes_per_class": (
                    (db_bytes + cache_bytes) / counts["classes"]
                ),
                "bytes_per_edge": db_bytes / counts["edges"],
            }

        warmup = analysis_run(
            wall=recorded["warmup_end_to_end_seconds"],
            cpu=recorded["warmup_cpu_seconds"],
            parser=recorded["warmup_parser_invocations"],
            hits=recorded["warmup_cache_hits"],
            peak=recorded["warmup_peak_rss_bytes"],
            stages=recorded["cold_stage_seconds"],
        )
        cold = analysis_run(
            wall=recorded["cold_end_to_end_seconds"],
            cpu=recorded["cold_cpu_seconds"],
            parser=recorded["cold_parser_invocations"],
            hits=0,
            peak=recorded["cold_peak_rss_bytes"],
            stages=recorded["cold_stage_seconds"],
        )
        warm_runs = [
            analysis_run(
                wall=wall,
                cpu=recorded["warm_cpu_seconds_samples"][index],
                parser=recorded["warm_parser_invocations_samples"][index],
                hits=recorded["warm_cache_hits_samples"][index],
                peak=recorded["warm_peak_rss_bytes_samples"][index],
                stages=recorded["warm_stage_seconds_samples"][index],
            )
            for index, wall in enumerate(
                recorded["warm_end_to_end_samples_seconds"]
            )
        ]
        legacy = {
            "end_to_end_seconds": float(recorded["legacy_end_to_end_seconds"]),
            "cpu_seconds": float(recorded["legacy_cpu_seconds"]),
            "average_cpu_cores": (
                float(recorded["legacy_cpu_seconds"])
                / float(recorded["legacy_end_to_end_seconds"])
            ),
            "class_count": 100_000,
            "peak_rss_bytes": int(recorded["legacy_peak_rss_bytes"]),
            "implementation": "legacy-javap-c-s-p-batched-per-artifact",
        }

        binding = {
            "schema": (
                "java-upgrade-analyzer.performance-authority-binding.v2"
            ),
            "authority_mode": authority_mode,
            "support_contract_identity": "8" * 64,
            "evidence_sha256": evidence_sha256,
            "source_implementation_identity": implementation[
                "source_implementation_identity"
            ],
        }
        binding["binding_identity"] = (
            binary_performance_gate.canonical_identity(
                "binary_performance_authority_binding_identity",
                {
                    field: binding[field]
                    for field in (
                        "support_contract_identity",
                        "evidence_sha256",
                        "source_implementation_identity",
                        "authority_mode",
                    )
                },
                schema_version="1",
            )
        )

        def raw_probe(name):
            probe = deepcopy(recorded[name])
            probe.pop("captured_at")
            probe.update({
                "performance_authority_mode": authority_mode,
                "activation_authority_mode": authority_mode,
                "pipeline_performance_authority_binding": dict(binding),
                "publication_deferred": False,
                "checkpoint_retained": False,
                "activation_candidate_discarded": (
                    authority_mode == "candidate_source_measurement"
                ),
                "activation_recapture_discarded": (
                    authority_mode == "release_recapture_measurement"
                ),
            })
            probe["average_cpu_cores"] = (
                float(probe["cpu_seconds"])
                / float(probe["end_to_end_seconds"])
            )
            return probe

        full = raw_probe("full_pipeline_probe")
        changed = raw_probe("changed_full_pipeline_probe")
        measured_runs = [cold, *warm_runs, legacy, full, changed]
        total_wall = sum(item["end_to_end_seconds"] for item in measured_runs)
        total_cpu = sum(item["cpu_seconds"] for item in measured_runs)
        measurements = {
            "warmup": warmup,
            "cold": cold,
            "warm_runs": warm_runs,
            "legacy": legacy,
            "full_pipeline_probe": full,
            "changed_full_pipeline_probe": changed,
            "warm_end_to_end_p50_seconds": (
                binary_performance_gate._p50([
                    item["end_to_end_seconds"] for item in warm_runs
                ])
            ),
            "warm_end_to_end_p95_seconds": (
                binary_performance_gate._p95([
                    item["end_to_end_seconds"] for item in warm_runs
                ])
            ),
            "cold_relative_legacy_ratio": (
                cold["end_to_end_seconds"] / legacy["end_to_end_seconds"]
            ),
            "total_measured_wall_seconds": total_wall,
            "total_measured_cpu_seconds": total_cpu,
            "average_cpu_cores": total_cpu / total_wall,
            "peak_rss_bytes": max([
                warmup["peak_rss_bytes"],
                *[item["peak_rss_bytes"] for item in measured_runs],
            ]),
            "disk_bytes": cold["db_bytes"] + cold["cache_bytes"],
        }
        return ({
            "schema": binary_performance_gate.SCHEMA,
            "status": "measured",
            "measurement_protocol": protocol,
            "measurements": measurements,
        }, policy, policy_identity, implementation)

    def _synthetic_current_provisional(self):
        candidate, _policy, _policy_identity, implementation = (
            self._synthetic_builder_raw_result()
        )
        candidate["measurement_protocol"]["release_policy_identity"] = (
            binary_performance_gate.release_policy_identity()
        )
        candidate_bytes = (
            json.dumps(candidate, ensure_ascii=False, sort_keys=True) + "\n"
        ).encode("utf-8")
        provisional = binary_performance_gate.build_recorded_gate_from_result(
            candidate_bytes,
            captured_at="2026-08-18T00:00:00Z",
            provisional=True,
        )
        return provisional, implementation

    def test_official_builder_completes_exact_candidate_to_final_chain(self):
        candidate, policy, policy_identity, _implementation = (
            self._synthetic_builder_raw_result()
        )
        candidate_bytes = (
            json.dumps(candidate, ensure_ascii=False, sort_keys=True, indent=1)
            + "\n"
        ).encode("utf-8")
        with patch.object(
            binary_performance_gate, "release_policy", return_value=policy,
        ), patch.object(
            binary_performance_gate,
            "release_policy_identity",
            return_value=policy_identity,
        ):
            provisional = (
                binary_performance_gate.build_recorded_gate_from_result(
                    candidate_bytes,
                    captured_at="2026-08-18T00:00:00Z",
                    provisional=True,
                )
            )
            provisional_bytes = (
                json.dumps(
                    provisional,
                    ensure_ascii=False,
                    sort_keys=False,
                    indent=3,
                ) + "\n"
            ).encode("utf-8")
            recapture, _, _, _ = self._synthetic_builder_raw_result(
                authority_mode="release_recapture_measurement",
                evidence_sha256=hashlib.sha256(
                    provisional_bytes
                ).hexdigest(),
            )
            recapture_bytes = (
                json.dumps(
                    recapture,
                    ensure_ascii=False,
                    sort_keys=False,
                    separators=(",", ":"),
                ) + "\n"
            ).encode("utf-8")
            final = binary_performance_gate.build_recorded_gate_from_result(
                recapture_bytes,
                captured_at="2026-08-18T01:00:00Z",
                provisional=False,
                provisional_gate_content=provisional_bytes,
            )
            with self.assertRaises(
                binary_performance_gate.PerformanceGateError
            ):
                binary_performance_gate.build_recorded_gate_from_result(
                    recapture_bytes,
                    captured_at="2026-08-18T00:00:00Z",
                    provisional=False,
                    provisional_gate_content=provisional_bytes,
                )
            with self.assertRaises(
                binary_performance_gate.PerformanceGateError
            ):
                binary_performance_gate.build_recorded_gate_from_result(
                    recapture_bytes,
                    captured_at="2026-08-18T01:00:00Z",
                    provisional=False,
                    provisional_gate_content=provisional_bytes + b" ",
                )
            with self.assertRaises(
                binary_performance_gate.PerformanceGateError
            ):
                binary_performance_gate.build_recorded_gate_from_result(
                    recapture_bytes,
                    captured_at="2026-08-18T01:00:00Z",
                    provisional=False,
                    provisional_gate_content=bytearray(provisional_bytes),
                )

        self.assertEqual(provisional["status"], "passed")
        self.assertEqual(
            provisional["measurement_provisional"][
                "candidate_result_sha256"
            ],
            hashlib.sha256(candidate_bytes).hexdigest(),
        )
        self.assertEqual(final["status"], "passed")
        self.assertNotIn("measurement_provisional", final)
        for name in ("full_pipeline_probe", "changed_full_pipeline_probe"):
            self.assertEqual(
                final["recorded_measurements"][name][
                    "pipeline_performance_authority_binding"
                ]["evidence_sha256"],
                hashlib.sha256(provisional_bytes).hexdigest(),
            )

    def test_official_builder_rejects_malformed_raw_and_metadata(self):
        raw, policy, policy_identity, _implementation = (
            self._synthetic_builder_raw_result()
        )

        def encoded(value, *, allow_nan=False):
            return (json.dumps(value, allow_nan=allow_nan) + "\n").encode(
                "utf-8"
            )

        malformed = []
        missing = deepcopy(raw)
        missing["measurements"].pop("disk_bytes")
        malformed.append(("missing field", encoded(missing)))
        string_numeric = deepcopy(raw)
        string_numeric["measurements"]["cold"][
            "end_to_end_seconds"
        ] = "1.0"
        malformed.append(("string numeric", encoded(string_numeric)))
        nonfinite = deepcopy(raw)
        nonfinite["measurements"]["cold"]["cpu_seconds"] = float("nan")
        malformed.append(("NaN", encoded(nonfinite, allow_nan=True)))
        inconsistent_binding = deepcopy(raw)
        inconsistent_binding["measurements"][
            "changed_full_pipeline_probe"
        ]["pipeline_performance_authority_binding"][
            "support_contract_identity"
        ] = "7" * 64
        malformed.append((
            "inconsistent probe binding",
            encoded(inconsistent_binding),
        ))
        narrowed_activation_scope = deepcopy(raw)
        narrowed_activation_scope["measurement_protocol"][
            "full_pipeline_probe"
        ]["validated_generation_activation_scope"] = "activate_only"
        malformed.append((
            "narrowed activation timing scope",
            encoded(narrowed_activation_scope),
        ))

        with patch.object(
            binary_performance_gate, "release_policy", return_value=policy,
        ), patch.object(
            binary_performance_gate,
            "release_policy_identity",
            return_value=policy_identity,
        ):
            for label, content in malformed:
                with self.subTest(label=label), self.assertRaises(
                    binary_performance_gate.PerformanceGateError
                ):
                    binary_performance_gate.build_recorded_gate_from_result(
                        content,
                        captured_at="2026-08-18T00:00:00Z",
                        provisional=True,
                    )
            for label, content, provisional in (
                ("non-bytes raw", "{}", True),
                ("non-boolean mode", encoded(raw), 1),
            ):
                with self.subTest(label=label), self.assertRaises(
                    binary_performance_gate.PerformanceGateError
                ):
                    binary_performance_gate.build_recorded_gate_from_result(
                        content,
                        captured_at="2026-08-18T00:00:00Z",
                        provisional=provisional,
                    )
            with self.assertRaises(binary_performance_gate.PerformanceGateError):
                binary_performance_gate.build_recorded_gate_from_result(
                    encoded(raw),
                    captured_at="2026-08-18",
                    provisional=True,
                )

    def _run_performance_cli(self, argv):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            try:
                return binary_performance_gate.main(argv)
            except SystemExit as error:
                return int(error.code or 0)

    def test_official_builder_cli_writes_replayable_provisional_evidence(self):
        raw, policy, policy_identity, _implementation = (
            self._synthetic_builder_raw_result()
        )
        raw_content = (
            json.dumps(raw, ensure_ascii=False, sort_keys=True) + "\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw_path = root / "candidate-result.json"
            output_path = root / "provisional-gate.json"
            raw_path.write_bytes(raw_content)
            with patch.object(
                binary_performance_gate, "release_policy", return_value=policy,
            ), patch.object(
                binary_performance_gate,
                "release_policy_identity",
                return_value=policy_identity,
            ):
                returncode = self._run_performance_cli([
                    "--build-provisional-from-result", str(raw_path),
                    "--captured-at", "2026-08-18T00:00:00Z",
                    "--output", str(output_path),
                ])
                evidence = binary_performance_gate._json_object_from_exact_bytes(
                    output_path.read_bytes(), field="cli_provisional_gate"
                )
                replay = binary_performance_gate.evaluate_provisional_gate(
                    evidence,
                    _current_source_implementation=evidence[
                        "measurement_protocol"
                    ]["implementation"],
                )

        self.assertEqual(returncode, 0)
        self.assertEqual(evidence["status"], "passed")
        self.assertEqual(replay["status"], "passed")
        self.assertEqual(
            evidence["measurement_provisional"]["candidate_result_sha256"],
            hashlib.sha256(raw_content).hexdigest(),
        )

    def test_cli_rejects_verify_and_benchmark_output_aliases_before_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gate_path = root / "gate.json"
            sentinel = b'{"schema":"sentinel"}\n'
            gate_path.write_bytes(sentinel)
            with patch.object(
                binary_performance_gate, "evaluate_recorded_gate",
                side_effect=AssertionError("verification must not start"),
            ) as verifier:
                verify_code = self._run_performance_cli([
                    "--verify-recorded-gate", str(gate_path),
                    "--output", str(gate_path),
                ])
            self.assertNotEqual(verify_code, 0)
            self.assertEqual(gate_path.read_bytes(), sentinel)
            verifier.assert_not_called()

            provisional_path = root / "provisional.json"
            provisional_path.write_bytes(sentinel)
            with patch.object(
                binary_performance_gate, "run_benchmark",
                side_effect=AssertionError("benchmark must not start"),
            ) as benchmark:
                provisional_code = self._run_performance_cli([
                    "--output", str(provisional_path),
                    "--provisional-gate", str(provisional_path),
                ])
            self.assertNotEqual(provisional_code, 0)
            self.assertEqual(provisional_path.read_bytes(), sentinel)
            benchmark.assert_not_called()

            with patch.object(
                binary_performance_gate, "run_benchmark",
                side_effect=AssertionError("benchmark must not start"),
            ) as benchmark:
                gate_code = self._run_performance_cli([
                    "--output", str(gate_path), "--gate", str(gate_path),
                ])
            self.assertNotEqual(gate_code, 0)
            self.assertEqual(gate_path.read_bytes(), sentinel)
            benchmark.assert_not_called()

    def test_cli_detects_hardlinked_builder_input_output_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw_path = root / "raw.json"
            output_path = root / "output.json"
            sentinel = b'{"schema":"raw-sentinel"}\n'
            raw_path.write_bytes(sentinel)
            try:
                os.link(raw_path, output_path)
            except OSError as error:
                self.skipTest(f"hardlinks are unavailable: {error}")
            with patch.object(
                binary_performance_gate,
                "build_recorded_gate_from_result",
                side_effect=AssertionError("builder must not start"),
            ) as builder:
                returncode = self._run_performance_cli([
                    "--build-provisional-from-result", str(raw_path),
                    "--captured-at", "2026-08-18T00:00:00Z",
                    "--output", str(output_path),
                ])

            self.assertNotEqual(returncode, 0)
            self.assertEqual(raw_path.read_bytes(), sentinel)
            self.assertEqual(output_path.read_bytes(), sentinel)
            builder.assert_not_called()

    def test_cli_replaces_stale_success_when_builder_raises_runtime_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw_path = root / "raw.json"
            output_path = root / "gate.json"
            raw_path.write_text("{}\n", encoding="utf-8")
            output_path.write_text(
                '{"schema":"stale","status":"passed"}\n',
                encoding="utf-8",
            )
            with patch.object(
                binary_performance_gate,
                "build_recorded_gate_from_result",
                side_effect=RuntimeError("injected builder crash"),
            ):
                returncode = self._run_performance_cli([
                    "--build-provisional-from-result", str(raw_path),
                    "--captured-at", "2026-08-18T00:00:00Z",
                    "--output", str(output_path),
                ])
            persisted = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(returncode, 1)
        self.assertEqual(persisted["status"], "failed")
        self.assertIn("RuntimeError", persisted["detail"])
        self.assertEqual(persisted["issue_count"], 1)
        self.assertEqual(
            persisted["issues"][0]["reason_code"],
            "BINARY_PERFORMANCE_EVIDENCE_BUILD_FAILED",
        )

    def test_final_builder_cli_preserves_structured_replay_issues(self):
        structured_issues = [
            {
                "reason_code": "BINARY_PERFORMANCE_THRESHOLD_EXCEEDED",
                "metric": "full_pipeline.validated_generation_activation",
                "actual": 3.8,
                "limit": 1.5,
            },
            {
                "reason_code": "BINARY_PERFORMANCE_THRESHOLD_EXCEEDED",
                "metric": (
                    "changed_full_pipeline."
                    "validated_generation_activation"
                ),
                "actual": 3.9,
                "limit": 1.5,
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw_path = root / "recapture.json"
            provisional_path = root / "provisional.json"
            output_path = root / "final.json"
            raw_path.write_text("{}\n", encoding="utf-8")
            provisional_path.write_text("{}\n", encoding="utf-8")
            output_path.write_text(
                '{"schema":"stale","status":"passed"}\n',
                encoding="utf-8",
            )
            with patch.object(
                binary_performance_gate,
                "build_recorded_gate_from_result",
                side_effect=binary_performance_gate.PerformanceGateError(
                    "built final evidence failed replay",
                    failure={
                        "reason_code": (
                            "BINARY_PERFORMANCE_BUILT_EVIDENCE_INVALID"
                        ),
                        "issues": structured_issues,
                    },
                ),
            ):
                returncode = self._run_performance_cli([
                    "--build-final-from-result", str(raw_path),
                    "--provisional-gate", str(provisional_path),
                    "--captured-at", "2026-08-18T01:00:00Z",
                    "--output", str(output_path),
                ])
            persisted = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(returncode, 1)
        self.assertEqual(
            persisted["reason_code"],
            "BINARY_PERFORMANCE_BUILT_EVIDENCE_INVALID",
        )
        self.assertEqual(persisted["issue_count"], 2)
        self.assertEqual(persisted["issues"], structured_issues)

    def test_successful_benchmark_cli_persists_result_exactly_once(self):
        result, _policy, _policy_identity, _implementation = (
            self._synthetic_builder_raw_result()
        )
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_performance_gate, "run_benchmark", return_value=result,
        ), patch.object(binary_performance_gate, "_write_json") as writer:
            root = Path(tmp)
            output_path = root / "result.json"
            returncode = self._run_performance_cli([
                "--work-root", str(root / "work"),
                "--output", str(output_path),
            ])

        self.assertEqual(returncode, 0)
        writer.assert_called_once_with(output_path.resolve(), result)

    def test_completed_benchmark_output_failure_preserves_recoverable_result(self):
        result, _policy, _policy_identity, _implementation = (
            self._synthetic_builder_raw_result()
        )
        real_write = binary_performance_gate._write_json
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            output = root / "requested-result.json"

            def fail_requested_output(path, value):
                if path == output.resolve():
                    raise OSError("injected requested sink failure")
                return real_write(path, value)

            with patch.object(
                binary_performance_gate,
                "run_benchmark",
                return_value=result,
            ), patch.object(
                binary_performance_gate,
                "_write_json",
                side_effect=fail_requested_output,
            ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                returncode = binary_performance_gate.main([
                    "--work-root", str(work),
                    "--output", str(output),
                ])

            recovery = (
                work
                / "binary_observability"
                / binary_performance_gate._PERFORMANCE_RECOVERY_RESULT_NAME
            )
            recovered_bytes = recovery.read_bytes()
            recovered = json.loads(recovered_bytes)
            failure = json.loads(stderr.getvalue().splitlines()[-1])

        self.assertEqual(returncode, 1)
        self.assertEqual(recovered, result)
        self.assertEqual(
            failure["reason_code"],
            "BINARY_PERFORMANCE_RESULT_PERSIST_FAILED",
        )
        self.assertEqual(failure["core_benchmark_status"], "completed")
        receipt = failure["core_result_receipt"]
        self.assertEqual(receipt["recovery_path"], str(recovery.resolve()))
        self.assertEqual(
            receipt["result_sha256"],
            hashlib.sha256(recovered_bytes).hexdigest(),
        )
        self.assertIn(
            "injected requested sink failure",
            failure["failure_result_persist_error"],
        )

    def test_failed_benchmark_with_broken_sink_and_unprintable_error_is_structured(self):
        class UnprintableError(RuntimeError):
            def __str__(self):
                raise RuntimeError("rendering failed")

        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_performance_gate,
            "run_benchmark",
            side_effect=UnprintableError(),
        ), patch.object(
            binary_performance_gate,
            "_write_json",
            side_effect=OSError("injected failure sink error"),
        ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            root = Path(tmp)
            returncode = binary_performance_gate.main([
                "--work-root", str(root / "work"),
                "--output", str(root / "result.json"),
            ])
            failure = json.loads(stderr.getvalue().splitlines()[-1])

        self.assertEqual(returncode, 1)
        self.assertEqual(
            failure["reason_code"],
            "BINARY_PERFORMANCE_FAILURE_RESULT_PERSIST_FAILED",
        )
        self.assertEqual(failure["core_benchmark_status"], "failed")
        self.assertIn(
            "unprintable UnprintableError",
            failure["primary_failure"]["detail"],
        )
        self.assertIn(
            "injected failure sink error",
            failure["failure_result_persist_error"],
        )

    def test_shared_performance_identity_helpers_reject_type_aliases(self):
        from binary_performance_identity import (
            generation_source_identity,
            is_sha256_identity,
            runtime_implementation_identity,
            source_implementation_identity,
        )

        class StringSubclass(str):
            pass

        valid_sha = "a" * 64
        self.assertTrue(is_sha256_identity(valid_sha))
        for invalid in (
            int("1" * 64), True, "A" * 64, "a" * 63,
            StringSubclass(valid_sha), None,
        ):
            with self.subTest(predicate_value=repr(invalid)):
                self.assertFalse(is_sha256_identity(invalid))

        records = [
            {"path": "scripts/source.py", "sha256": valid_sha},
            {"path": "@runtime/jdk", "sha256": "b" * 64},
        ]
        self.assertRegex(generation_source_identity(records), r"^[0-9a-f]{64}$")
        invalid_record_sets = (
            "scripts/source.py",
            [{"path": 1, "sha256": valid_sha}],
            [{"path": "scripts/source.py", "sha256": int("1" * 64)}],
            [{"path": "scripts/source.py", "sha256": valid_sha, "extra": 1}],
            [{"path": "@runtime/jdk", "sha256": int("1" * 64)}],
            [records[0], dict(records[0])],
        )
        for invalid in invalid_record_sets:
            with self.subTest(records=repr(invalid)), self.assertRaises(
                (TypeError, ValueError)
            ):
                generation_source_identity(invalid)

        source_components = {
            "generation_source_identity": "1" * 64,
            "validator_source_identity": "2" * 64,
            "oracle_support_manifest_identity": "3" * 64,
            "harness_source_identity": "4" * 64,
        }
        source_identity = source_implementation_identity(source_components)
        runtime_components = {
            "source_implementation_identity": source_identity,
            "pipeline_generation_implementation_identity": "5" * 64,
            "validator_implementation_identity": "6" * 64,
            "jdk_preflight_identity": "7" * 64,
        }
        self.assertRegex(
            runtime_implementation_identity(runtime_components),
            r"^[0-9a-f]{64}$",
        )
        for builder, components, field in (
            (
                source_implementation_identity,
                source_components,
                "generation_source_identity",
            ),
            (
                runtime_implementation_identity,
                runtime_components,
                "jdk_preflight_identity",
            ),
        ):
            for invalid in (True, int("8" * 64), "F" * 64, None):
                malformed = dict(components)
                malformed[field] = invalid
                with self.subTest(
                    builder=builder.__name__, invalid=repr(invalid)
                ), self.assertRaises(ValueError):
                    builder(malformed)

    def test_invalid_cached_dataset_manifest_is_rebuilt_before_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = binary_performance_gate.build_dataset(
                root, jar_count=1, classes_per_jar=2
            )
            manifest_path = root / "dataset" / "manifest.json"
            malformed = json.loads(manifest_path.read_text(encoding="utf-8"))
            malformed["artifacts"][0]["byte_length"] = True
            manifest_path.write_text(
                json.dumps(malformed) + "\n", encoding="utf-8"
            )

            rebuilt = binary_performance_gate.build_dataset(
                root, jar_count=1, classes_per_jar=2
            )
            repaired = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(
            [item["sha256"] for item in rebuilt],
            [item["sha256"] for item in first],
        )
        self.assertIs(type(repaired["artifacts"][0]["byte_length"]), int)
        self.assertGreater(repaired["artifacts"][0]["byte_length"], 0)

    def test_dataset_zip_publication_never_follows_existing_file_links(self):
        original_compile = binary_performance_gate._compile_template
        completed = []
        for link_kind in ("symlink", "hardlink"):
            with self.subTest(link_kind=link_kind), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                external = root / "external-sentinel.bin"
                sentinel = b"external dataset sentinel must remain unchanged"
                external.write_bytes(sentinel)

                def inject_link(template_root, **kwargs):
                    target = (
                        Path(template_root) / "dataset" / "artifact-0000.jar"
                    )
                    try:
                        if link_kind == "symlink":
                            target.symlink_to(external)
                        else:
                            os.link(external, target)
                    except OSError:
                        return original_compile(template_root, **kwargs)
                    completed.append(link_kind)
                    return original_compile(template_root, **kwargs)

                with patch.object(
                    binary_performance_gate,
                    "_compile_template",
                    side_effect=inject_link,
                ):
                    artifacts = binary_performance_gate.build_dataset(
                        root, jar_count=1, classes_per_jar=2
                    )

                artifact_path = Path(artifacts[0]["path"])
                self.assertEqual(external.read_bytes(), sentinel)
                self.assertFalse(artifact_path.is_symlink())
                self.assertNotEqual(
                    os.stat(artifact_path).st_ino, os.stat(external).st_ino
                )
                self.assertTrue(zipfile.is_zipfile(artifact_path))

        self.assertTrue(completed, "filesystem exposes no testable link type")

    def test_changed_zip_publication_never_follows_existing_file_links(self):
        completed = []
        for link_kind in ("symlink", "hardlink"):
            with self.subTest(link_kind=link_kind), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                artifacts = binary_performance_gate.build_dataset(
                    root, jar_count=1, classes_per_jar=2
                )
                changed_directory = root / "changed-dataset"
                changed_directory.mkdir()
                changed_path = changed_directory / "artifact-0000.jar"
                external = root / "external-changed-sentinel.bin"
                sentinel = b"external changed sentinel must remain unchanged"
                external.write_bytes(sentinel)
                try:
                    if link_kind == "symlink":
                        changed_path.symlink_to(external)
                    else:
                        os.link(external, changed_path)
                except OSError:
                    continue
                completed.append(link_kind)

                changed = (
                    binary_performance_gate.build_changed_current_artifacts(
                        root, artifacts, classes_per_jar=2
                    )
                )

                published_path = Path(changed[0]["path"])
                self.assertEqual(external.read_bytes(), sentinel)
                self.assertFalse(published_path.is_symlink())
                self.assertNotEqual(
                    os.stat(published_path).st_ino, os.stat(external).st_ino
                )
                self.assertTrue(zipfile.is_zipfile(published_path))

        self.assertTrue(completed, "filesystem exposes no testable link type")

    def test_dataset_builders_reject_linked_output_directories(self):
        for directory_name in ("dataset", "changed-dataset"):
            with self.subTest(directory=directory_name), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "work"
                root.mkdir()
                external = Path(tmp) / "external"
                external.mkdir()
                sentinel_path = external / "sentinel.txt"
                sentinel_path.write_text("unchanged", encoding="utf-8")
                try:
                    (root / directory_name).symlink_to(
                        external, target_is_directory=True
                    )
                except OSError as error:
                    self.skipTest(f"directory symlinks are unavailable: {error}")

                with self.assertRaisesRegex(
                    binary_performance_gate.PerformanceGateError,
                    "physical directory",
                ):
                    if directory_name == "dataset":
                        binary_performance_gate.build_dataset(
                            root, jar_count=1, classes_per_jar=1
                        )
                    else:
                        binary_performance_gate.build_changed_current_artifacts(
                            root,
                            [{"first_class_index": 0}],
                            classes_per_jar=1,
                        )

                self.assertEqual(
                    sentinel_path.read_text(encoding="utf-8"), "unchanged"
                )
                self.assertFalse((external / "artifact-0000.jar").exists())
                self.assertFalse((external / "manifest.json").exists())

    def test_isolated_probe_rejects_linked_coordinator_directory(self):
        for directory_name in (
            "identical-full-pipeline", "changed-full-pipeline",
        ):
            with self.subTest(directory=directory_name), \
                    tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp) / "work"
                parent.mkdir()
                external = Path(tmp) / "external"
                external.mkdir()
                sentinel_path = external / "sentinel.txt"
                sentinel_path.write_text("unchanged", encoding="utf-8")
                probe_root = parent / directory_name
                try:
                    probe_root.symlink_to(external, target_is_directory=True)
                except OSError as error:
                    self.skipTest(f"directory symlinks are unavailable: {error}")

                with patch.object(
                    binary_performance_gate,
                    "run_managed_subprocess",
                    side_effect=AssertionError("worker must not start"),
                ) as worker, self.assertRaisesRegex(
                    binary_performance_gate.PerformanceGateError,
                    "physical directory",
                ):
                    binary_performance_gate._run_isolated_full_pipeline_probe(
                        [],
                        root=probe_root,
                        asm_jar=Path("/unused/asm.jar"),
                        classes_per_jar=1,
                        expected_implementation={},
                    )

                worker.assert_not_called()
                self.assertEqual(
                    sentinel_path.read_text(encoding="utf-8"), "unchanged"
                )
                self.assertFalse(
                    (external / "isolated_probe_input.json").exists()
                )
                self.assertFalse(
                    (external / "isolated_probe_result.json").exists()
                )

    def test_cli_rejects_linked_work_root_without_touching_external_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "parent"
            parent.mkdir()
            external = Path(tmp) / "external"
            external.mkdir()
            sentinel_path = external / "sentinel.txt"
            sentinel_path.write_text("unchanged", encoding="utf-8")
            work_root = parent / "linked-work-root"
            try:
                work_root.symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            with patch.object(
                binary_performance_gate,
                "run_benchmark",
                side_effect=AssertionError("benchmark must not start"),
            ) as benchmark:
                returncode = self._run_performance_cli([
                    "--work-root", str(work_root),
                    "--output", str(parent / "result.json"),
                ])

            self.assertNotEqual(returncode, 0)
            benchmark.assert_not_called()
            self.assertEqual(
                sentinel_path.read_text(encoding="utf-8"), "unchanged"
            )
            self.assertEqual(
                sorted(path.name for path in external.iterdir()), ["sentinel.txt"]
            )

    def test_work_root_allows_canonicalized_parent_directory_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            physical_parent = root / "physical-parent"
            physical_parent.mkdir()
            linked_parent = root / "linked-parent"
            try:
                linked_parent.symlink_to(
                    physical_parent, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")
            work_root = linked_parent / "physical-leaf"

            with patch.object(
                binary_performance_gate,
                "resolve_asm_jar",
                side_effect=RuntimeError("stop after work-root validation"),
            ), self.assertRaisesRegex(
                RuntimeError, "stop after work-root validation"
            ):
                binary_performance_gate.run_benchmark(
                    work_root, jar_count=1, classes_per_jar=1,
                    warm_samples=1, include_legacy=False,
                )

            self.assertTrue((physical_parent / "physical-leaf").is_dir())
            self.assertFalse((physical_parent / "physical-leaf").is_symlink())

    def test_benchmark_freezes_provisional_bytes_for_both_long_probes(self):
        original_content = b'{"schema":"provisional-original"}\n'
        replacement_content = b'{"schema":"provisional-replaced"}\n'
        expected_sha256 = hashlib.sha256(original_content).hexdigest()
        implementation = {
            "source_implementation_identity": "1" * 64,
            "runtime_implementation_identity": "2" * 64,
        }
        reference_runtime = {
            "machine_identity": "3" * 64,
            "machine": {},
            "tool_versions": {},
            "cpu_time_source": "test",
            "peak_rss_source": "test",
        }
        artifacts = [{"sha256": "4" * 64}]
        changed_artifacts = [{"sha256": "5" * 64}]

        def analysis_run(parser_invocations):
            return {
                "end_to_end_seconds": 1.0,
                "cpu_seconds": 0.5,
                "parser_invocations": parser_invocations,
                "counts": {"classes": 1},
                "peak_rss_bytes": 1024,
                "db_bytes": 10,
                "cache_bytes": 20,
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "benchmark"
            provisional = Path(tmp) / "provisional.json"
            provisional.write_bytes(original_content)
            observed_probe_inputs = []
            observed_preflight_inputs = []

            def preflight(_implementation, *, provisional_gate_path):
                observed_preflight_inputs.append(
                    (provisional_gate_path, provisional_gate_path.read_bytes())
                )

            def run_probe(_artifacts, **kwargs):
                snapshot_path = kwargs["provisional_gate_path"]
                observed_probe_inputs.append(
                    (snapshot_path, snapshot_path.read_bytes())
                )
                if len(observed_probe_inputs) == 1:
                    provisional.write_bytes(replacement_content)
                return {
                    "jar_count": 1,
                    "class_count": 1,
                    "comparison": (
                        "identical"
                        if kwargs.get("current_artifacts") is None
                        else "changed"
                    ),
                    "end_to_end_seconds": 1.0,
                    "cpu_seconds": 0.5,
                    "peak_rss_bytes": 2048,
                    "pipeline_performance_authority_binding": {
                        "evidence_sha256": expected_sha256,
                    },
                }

            with patch.object(
                binary_performance_gate,
                "resolve_asm_jar",
                return_value=Path("/synthetic/asm.jar"),
            ), patch.object(
                binary_performance_gate,
                "_performance_implementation_protocol",
                return_value=implementation,
            ), patch.object(
                binary_performance_gate,
                "evaluate_provisional_gate",
                return_value={"status": "passed", "issues": []},
            ), patch.object(
                binary_performance_gate,
                "_reference_runtime_protocol",
                return_value=reference_runtime,
            ), patch.object(
                binary_performance_gate,
                "_preflight_performance_authority",
                side_effect=preflight,
            ), patch.object(
                binary_performance_gate,
                "build_dataset",
                return_value=artifacts,
            ), patch.object(
                binary_performance_gate,
                "build_changed_current_artifacts",
                return_value=changed_artifacts,
            ), patch.object(
                binary_performance_gate,
                "_analyze_once",
                side_effect=[
                    analysis_run(1),
                    analysis_run(1),
                    analysis_run(0),
                ],
            ), patch.object(
                binary_performance_gate,
                "_run_isolated_full_pipeline_probe",
                side_effect=run_probe,
            ):
                result = binary_performance_gate.run_benchmark(
                    root,
                    jar_count=1,
                    classes_per_jar=1,
                    warm_samples=1,
                    include_legacy=False,
                    provisional_gate_path=provisional,
                )

            self.assertEqual(provisional.read_bytes(), replacement_content)
            self.assertEqual(len(observed_preflight_inputs), 1)
            self.assertEqual(len(observed_probe_inputs), 2)
            preflight_path, preflight_content = observed_preflight_inputs[0]
            first_path, first_content = observed_probe_inputs[0]
            second_path, second_content = observed_probe_inputs[1]
            self.assertEqual(preflight_path, first_path)
            self.assertEqual(preflight_content, original_content)
            self.assertEqual(first_path, second_path)
            self.assertNotEqual(first_path, provisional.resolve())
            self.assertEqual((first_content, second_content), (
                original_content, original_content,
            ))
            self.assertEqual(
                first_path.parent, root.resolve() / "provisional-authority"
            )
            self.assertIn(expected_sha256, first_path.name)
            for name in (
                "full_pipeline_probe", "changed_full_pipeline_probe",
            ):
                self.assertEqual(
                    result["measurements"][name][
                        "pipeline_performance_authority_binding"
                    ]["evidence_sha256"],
                    expected_sha256,
                )

    def test_provisional_snapshot_failure_precedes_expensive_dataset_work(self):
        implementation = {
            "source_implementation_identity": "1" * 64,
            "runtime_implementation_identity": "2" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "benchmark"
            provisional = Path(tmp) / "provisional.json"
            provisional.write_text("{}\n", encoding="utf-8")
            with patch.object(
                binary_performance_gate,
                "resolve_asm_jar",
                return_value=Path("/synthetic/asm.jar"),
            ), patch.object(
                binary_performance_gate,
                "_performance_implementation_protocol",
                return_value=implementation,
            ), patch.object(
                binary_performance_gate,
                "evaluate_provisional_gate",
                return_value={"status": "passed", "issues": []},
            ), patch.object(
                binary_performance_gate,
                "_write_exact_bytes",
                side_effect=OSError("injected snapshot write failure"),
            ), patch.object(
                binary_performance_gate,
                "build_dataset",
                side_effect=AssertionError("dataset work must not start"),
            ) as dataset, self.assertRaises(
                binary_performance_gate.PerformanceGateError
            ) as raised:
                binary_performance_gate.run_benchmark(
                    root,
                    jar_count=1,
                    classes_per_jar=1,
                    warm_samples=1,
                    include_legacy=False,
                    provisional_gate_path=provisional,
                )

            dataset.assert_not_called()
            self.assertEqual(
                raised.exception.failure["reason_code"],
                "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID",
            )
            self.assertIn("injected snapshot write failure", str(raised.exception))

    def test_authority_preflight_failure_precedes_expensive_dataset_work(self):
        implementation = {
            "source_implementation_identity": "1" * 64,
            "runtime_implementation_identity": "2" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "benchmark"
            provisional = Path(tmp) / "provisional.json"
            provisional.write_text("{}\n", encoding="utf-8")
            with patch.object(
                binary_performance_gate,
                "resolve_asm_jar",
                return_value=Path("/synthetic/asm.jar"),
            ), patch.object(
                binary_performance_gate,
                "_performance_implementation_protocol",
                return_value=implementation,
            ), patch.object(
                binary_performance_gate,
                "evaluate_provisional_gate",
                return_value={"status": "passed", "issues": []},
            ), patch.object(
                binary_performance_gate,
                "_preflight_performance_authority",
                side_effect=binary_performance_gate.PerformanceGateError(
                    "injected authority preflight failure",
                    failure={
                        "reason_code": (
                            "BINARY_PERFORMANCE_AUTHORITY_PREFLIGHT_FAILED"
                        )
                    },
                ),
            ) as preflight, patch.object(
                binary_performance_gate,
                "build_dataset",
                side_effect=AssertionError("dataset work must not start"),
            ) as dataset, self.assertRaises(
                binary_performance_gate.PerformanceGateError
            ) as raised:
                binary_performance_gate.run_benchmark(
                    root,
                    jar_count=1,
                    classes_per_jar=1,
                    warm_samples=1,
                    include_legacy=False,
                    provisional_gate_path=provisional,
                )

            preflight.assert_called_once()
            dataset.assert_not_called()
            self.assertEqual(
                raised.exception.failure["reason_code"],
                "BINARY_PERFORMANCE_AUTHORITY_PREFLIGHT_FAILED",
            )

    def test_provisional_probe_binding_rejects_snapshot_sha_mismatch(self):
        with self.assertRaises(
            binary_performance_gate.PerformanceGateError
        ) as raised:
            binary_performance_gate._require_provisional_probe_binding(
                {
                    "pipeline_performance_authority_binding": {
                        "evidence_sha256": "1" * 64,
                    },
                },
                expected_evidence_sha256="2" * 64,
                field="full_pipeline_probe",
            )

        self.assertEqual(
            raised.exception.failure["reason_code"],
            "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
        )

    def test_provisional_snapshot_rejects_linked_private_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "benchmark"
            root.mkdir()
            external = Path(tmp) / "external"
            external.mkdir()
            sentinel = external / "sentinel.txt"
            sentinel.write_text("unchanged", encoding="utf-8")
            authority_root = root / "provisional-authority"
            try:
                authority_root.symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            with self.assertRaisesRegex(
                binary_performance_gate.PerformanceGateError,
                "physical directory",
            ):
                binary_performance_gate._snapshot_provisional_gate(
                    root, b"{}\n"
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
            self.assertEqual(
                sorted(path.name for path in external.iterdir()),
                ["sentinel.txt"],
            )

    def test_cli_rejects_output_leaf_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw_path = root / "raw.json"
            raw_path.write_text("{}\n", encoding="utf-8")
            external = root / "external-sentinel.json"
            sentinel = b'{"status":"external-must-not-change"}\n'
            external.write_bytes(sentinel)
            output_path = root / "linked-output.json"
            try:
                output_path.symlink_to(external)
            except OSError as error:
                self.skipTest(f"file symlinks are unavailable: {error}")

            with patch.object(
                binary_performance_gate,
                "build_recorded_gate_from_result",
                side_effect=AssertionError("builder must not start"),
            ) as builder:
                returncode = self._run_performance_cli([
                    "--build-provisional-from-result", str(raw_path),
                    "--captured-at", "2026-08-18T00:00:00Z",
                    "--output", str(output_path),
                ])

            self.assertNotEqual(returncode, 0)
            builder.assert_not_called()
            self.assertTrue(output_path.is_symlink())
            self.assertEqual(external.read_bytes(), sentinel)

    def test_cli_rejects_dangling_work_root_and_output_leaf_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing_directory = root / "missing-external-directory"
            work_root = root / "dangling-work-root"
            missing_output_target = root / "missing-external-output.json"
            output_path = root / "dangling-output.json"
            try:
                work_root.symlink_to(
                    missing_directory, target_is_directory=True
                )
                output_path.symlink_to(missing_output_target)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")

            with patch.object(
                binary_performance_gate,
                "run_benchmark",
                side_effect=AssertionError("benchmark must not start"),
            ) as benchmark:
                work_code = self._run_performance_cli([
                    "--work-root", str(work_root),
                    "--output", str(root / "result.json"),
                ])
            benchmark.assert_not_called()

            raw_path = root / "raw.json"
            raw_path.write_text("{}\n", encoding="utf-8")
            with patch.object(
                binary_performance_gate,
                "build_recorded_gate_from_result",
                side_effect=AssertionError("builder must not start"),
            ) as builder:
                output_code = self._run_performance_cli([
                    "--build-provisional-from-result", str(raw_path),
                    "--captured-at", "2026-08-18T00:00:00Z",
                    "--output", str(output_path),
                ])
            builder.assert_not_called()

            self.assertNotEqual(work_code, 0)
            self.assertNotEqual(output_code, 0)
            self.assertTrue(work_root.is_symlink())
            self.assertTrue(output_path.is_symlink())
            self.assertFalse(missing_directory.exists())
            self.assertFalse(missing_output_target.exists())

    def test_sqlite_leaf_cleanup_never_follows_links(self):
        completed = []
        for link_kind in ("symlink", "dangling-symlink", "hardlink"):
            with self.subTest(link_kind=link_kind), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output_path = root / "cold.sqlite"
                external = root / "external.sqlite"
                sentinel = b"external sqlite sentinel"
                if link_kind != "dangling-symlink":
                    external.write_bytes(sentinel)
                try:
                    if link_kind == "hardlink":
                        os.link(external, output_path)
                    else:
                        output_path.symlink_to(external)
                except OSError:
                    continue
                completed.append(link_kind)

                binary_performance_gate._remove_existing_regular_or_link_leaf(
                    output_path, field="test SQLite output"
                )
                with self.assertRaises(FileNotFoundError):
                    os.lstat(output_path)
                output_path.write_bytes(b"new private database")

                if link_kind == "dangling-symlink":
                    self.assertFalse(external.exists())
                else:
                    self.assertEqual(external.read_bytes(), sentinel)
                    self.assertNotEqual(
                        os.stat(output_path).st_ino, os.stat(external).st_ino
                    )

        self.assertTrue(completed, "filesystem exposes no testable link type")

    def test_analysis_opens_private_sqlite_after_unlinking_leaf_link(self):
        cases = ((False, True), (True, False))
        for warm, target_exists in cases:
            with self.subTest(warm=warm, target_exists=target_exists), \
                    tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "work"
                root.mkdir()
                cache_root = root / "cache"
                if warm:
                    cache_root.mkdir()
                db_path = root / ("warm.sqlite" if warm else "cold.sqlite")
                external = Path(tmp) / "external.sqlite"
                sentinel = b"external sqlite must not change"
                if target_exists:
                    external.write_bytes(sentinel)
                try:
                    db_path.symlink_to(external)
                except OSError as error:
                    self.skipTest(f"file symlinks are unavailable: {error}")

                def open_private_store(path):
                    observed = Path(path)
                    self.assertEqual(observed, db_path)
                    self.assertFalse(observed.is_symlink())
                    observed.write_bytes(b"private sqlite bytes")
                    raise RuntimeError("stop after SQLite path open")

                with patch.object(
                    binary_performance_gate, "_jdk_home",
                    return_value=Path("/unused/jdk"),
                ), patch.object(
                    binary_performance_gate, "_java_major", return_value=17,
                ), patch.object(
                    binary_performance_gate, "_runtime_profile",
                    return_value=object(),
                ), patch.object(
                    binary_performance_gate,
                    "BinaryFactStore",
                    side_effect=open_private_store,
                ), self.assertRaisesRegex(
                    RuntimeError, "stop after SQLite path open"
                ):
                    binary_performance_gate._analyze_once(
                        [], root=root, cache_root=cache_root,
                        asm_jar=Path("/unused/asm.jar"), warm=warm,
                    )

                self.assertEqual(db_path.read_bytes(), b"private sqlite bytes")
                if target_exists:
                    self.assertEqual(external.read_bytes(), sentinel)
                else:
                    self.assertFalse(external.exists())

    def test_analysis_rejects_linked_cache_directory_before_tool_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "work"
            root.mkdir()
            external = Path(tmp) / "external-cache"
            external.mkdir()
            sentinel_path = external / "sentinel.txt"
            sentinel_path.write_text("unchanged", encoding="utf-8")
            cache_root = root / "cache"
            try:
                cache_root.symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            with patch.object(
                binary_performance_gate,
                "_jdk_home",
                side_effect=AssertionError("tool discovery must not start"),
            ) as discover, self.assertRaisesRegex(
                binary_performance_gate.PerformanceGateError,
                "physical directory",
            ):
                binary_performance_gate._analyze_once(
                    [], root=root, cache_root=cache_root,
                    asm_jar=Path("/unused/asm.jar"), warm=False,
                )

            discover.assert_not_called()
            self.assertEqual(
                sentinel_path.read_text(encoding="utf-8"), "unchanged"
            )

    def test_percentile_of_integer_samples_has_canonical_float_type(self):
        median = binary_performance_gate._percentile([1, 2, 3], 0.5)
        maximum = binary_performance_gate._percentile([1, 2, 3], 1.0)

        self.assertEqual((median, maximum), (2.0, 3.0))
        self.assertIs(type(median), float)
        self.assertIs(type(maximum), float)

    def test_performance_gate_source_has_no_duplicate_literal_dict_keys(self):
        import ast

        source_path = ROOT_DIR / "scripts" / "binary_performance_gate.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        duplicates = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            literal_keys = [
                key.value
                for key in node.keys
                if isinstance(key, ast.Constant)
                and isinstance(key.value, (str, int, float, bytes))
            ]
            repeated = sorted({
                key for key in literal_keys if literal_keys.count(key) > 1
            }, key=repr)
            if repeated:
                duplicates.append((node.lineno, repeated))

        self.assertEqual(duplicates, [])

    def test_small_fixture_enforces_class_conservation_and_zero_warm_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_benchmark(
                Path(tmp),
                jar_count=2,
                classes_per_jar=3,
                warm_samples=1,
                include_legacy=True,
            )

        self.assertEqual(result["measurement_protocol"]["class_count"], 6)
        self.assertEqual(result["measurements"]["cold"]["counts"]["classes"], 6)
        self.assertGreater(
            result["measurements"]["cold"]["parser_invocations"], 0
        )
        self.assertEqual(
            result["measurements"]["warm_runs"][0]["parser_invocations"], 0
        )
        self.assertEqual(
            result["measurements"]["warm_runs"][0]["cache_hits"], 2
        )
        warm = result["measurements"]["warm_runs"][0]
        self.assertGreaterEqual(warm["cpu_seconds"], 0)
        self.assertGreaterEqual(warm["average_cpu_cores"], 0)
        self.assertEqual(
            result["measurements"]["warm_end_to_end_p50_seconds"],
            warm["end_to_end_seconds"],
        )
        self.assertGreater(result["measurements"]["total_measured_cpu_seconds"], 0)
        self.assertGreater(result["measurements"]["average_cpu_cores"], 0)
        self.assertEqual(
            result["measurements"]["legacy"]["class_count"], 6,
        )
        self.assertEqual(
            result["measurements"]["legacy"]["implementation"],
            "legacy-javap-c-s-p-batched-per-artifact",
        )
        full_pipeline = result["measurements"]["full_pipeline_probe"]
        self.assertEqual(full_pipeline["status"], "passed")
        self.assertEqual(full_pipeline["jar_count"], 2)
        self.assertEqual(full_pipeline["class_count"], 6)
        self.assertEqual(full_pipeline["base_class_count"], 6)
        self.assertEqual(full_pipeline["current_class_count"], 6)
        self.assertEqual(full_pipeline["validation_issue_count"], 0)
        self.assertEqual(full_pipeline["authoritative_change_fact_count"], 0)
        self.assertEqual(full_pipeline["formal_api_result_count"], 0)
        self.assertEqual(full_pipeline["parser_invocations"], 2)
        self.assertEqual(full_pipeline["artifact_snapshot_hits"], 0)
        self.assertNotEqual(full_pipeline["process_id"], os.getpid())
        self.assertEqual(
            full_pipeline["rss_measurement_scope"],
            "dedicated_probe_process_and_completed_children",
        )
        self.assertGreater(full_pipeline["peak_rss_bytes"], 0)
        self.assertIn(
            "target_independent_runtime_reconciliation",
            full_pipeline["phase_seconds"],
        )
        self.assertIn("independent_validation", full_pipeline["phase_seconds"])
        self.assertEqual(
            set(full_pipeline["phase_peak_rss_bytes"]),
            set(full_pipeline["phase_seconds"]),
        )
        self.assertLessEqual(
            max(full_pipeline["phase_peak_rss_bytes"].values()),
            full_pipeline["peak_rss_bytes"],
        )
        changed_full_pipeline = result["measurements"][
            "changed_full_pipeline_probe"
        ]
        self.assertEqual(changed_full_pipeline["status"], "passed")
        self.assertEqual(
            changed_full_pipeline["comparison"],
            "nonidentical-base-current-cold-output",
        )
        self.assertEqual(changed_full_pipeline["base_class_count"], 6)
        self.assertEqual(changed_full_pipeline["current_class_count"], 6)
        self.assertEqual(changed_full_pipeline["validation_issue_count"], 0)
        self.assertEqual(
            changed_full_pipeline["authoritative_change_fact_count"], 3
        )
        self.assertEqual(
            changed_full_pipeline[
                "authoritative_member_change_kind_counts"
            ],
            {"implementation_changed": 3},
        )
        self.assertEqual(changed_full_pipeline["formal_api_result_count"], 3)
        self.assertEqual(
            changed_full_pipeline["formal_reachability_status_counts"],
            {"not_found_in_static_analysis": 3},
        )
        self.assertEqual(
            changed_full_pipeline["formal_impact_conclusion_counts"],
            {"inconclusive": 3},
        )
        self.assertEqual(changed_full_pipeline["parser_invocations"], 3)
        self.assertEqual(
            changed_full_pipeline["artifact_snapshot_memory_hits"], 1
        )
        self.assertEqual(changed_full_pipeline["artifact_snapshot_hits"], 1)
        self.assertNotEqual(changed_full_pipeline["process_id"], os.getpid())
        self.assertNotEqual(
            changed_full_pipeline["process_id"], full_pipeline["process_id"]
        )
        protocol = result["measurement_protocol"]
        implementation = protocol["implementation"]
        self.assertEqual(
            protocol["source_implementation_identity"],
            binary_performance_gate._source_implementation_identity(
                implementation
            ),
        )
        self.assertEqual(
            protocol["runtime_implementation_identity"],
            binary_performance_gate._runtime_implementation_identity(
                implementation
            ),
        )
        self.assertEqual(
            protocol["full_pipeline_probe"]["process_isolation"],
            "dedicated_python_process",
        )
        self.assertIn(
            "static_preflight",
            protocol["full_pipeline_probe"]["includes"],
        )
        self.assertEqual(
            protocol["full_pipeline_probe"][
                "validated_generation_activation_scope"
            ],
            binary_performance_gate.VALIDATED_GENERATION_ACTIVATION_SCOPE,
        )
        cold = result["measurements"]["cold"]
        gate = {
            "measurement_protocol": {
                "machine_identity": protocol["machine_identity"],
                "dataset_identity": protocol["dataset_identity"],
                "jar_count": 2,
                "class_count": 6,
                "source_implementation_identity": protocol[
                    "source_implementation_identity"
                ],
                "runtime_implementation_identity": protocol[
                    "runtime_implementation_identity"
                ],
                "full_pipeline_probe": protocol["full_pipeline_probe"],
                "changed_full_pipeline_probe": protocol[
                    "changed_full_pipeline_probe"
                ],
            },
            "thresholds": {
                "cold_end_to_end_seconds": cold["end_to_end_seconds"] * 2,
                "warm_end_to_end_p50_seconds": result["measurements"]["warm_end_to_end_p50_seconds"] * 2,
                "warm_end_to_end_p95_seconds": result["measurements"]["warm_end_to_end_p95_seconds"] * 2,
                "peak_rss_bytes": result["measurements"]["peak_rss_bytes"] * 2,
                "disk_bytes": result["measurements"]["disk_bytes"] * 2,
                "bytes_per_class": cold["bytes_per_class"] * 2,
                "bytes_per_edge": cold["bytes_per_edge"] * 2,
                "cold_relative_legacy_ratio": 10,
                "warm_relative_legacy_ratio": 10,
                "full_pipeline_end_to_end_seconds": (
                    full_pipeline["end_to_end_seconds"] * 2
                ),
                "full_pipeline_peak_rss_bytes": (
                    full_pipeline["peak_rss_bytes"] * 2
                ),
                "full_pipeline_phase_seconds": {
                    phase: seconds * 2 + 0.001
                    for phase, seconds in full_pipeline["phase_seconds"].items()
                },
                "changed_full_pipeline_end_to_end_seconds": (
                    changed_full_pipeline["end_to_end_seconds"] * 2
                ),
                "changed_full_pipeline_peak_rss_bytes": (
                    changed_full_pipeline["peak_rss_bytes"] * 2
                ),
                "changed_full_pipeline_phase_seconds": {
                    phase: seconds * 2 + 0.001
                    for phase, seconds in changed_full_pipeline[
                        "phase_seconds"
                    ].items()
                },
                "stage_p95_seconds": {
                    "inventory": 10,
                    "parse_and_cache": 10,
                    "db_write_and_index": 10,
                    "batch_query_10000": 10,
                    "report_10000": 10,
                },
            },
            "accuracy_invariants": {
                "expected_class_count": cold["counts"]["classes"],
                "expected_member_count": cold["counts"]["members"],
                "expected_edge_count": cold["counts"]["edges"],
                "warm_parser_invocations": 0,
                "full_pipeline_expected_class_count": 6,
                "full_pipeline_expected_parser_invocations": 2,
                "full_pipeline_expected_artifact_snapshot_hits": 0,
                "full_pipeline_validation_issue_count": 0,
                "full_pipeline_expected_authoritative_change_fact_count": 0,
                "full_pipeline_expected_formal_api_result_count": 0,
                "full_pipeline_expected_authoritative_member_change_kind_counts": {},
                "full_pipeline_expected_formal_reachability_status_counts": {},
                "full_pipeline_expected_formal_impact_conclusion_counts": {},
                "changed_full_pipeline_expected_class_count": 6,
                "changed_full_pipeline_expected_parser_invocations": 3,
                "changed_full_pipeline_expected_artifact_snapshot_hits": 1,
                "changed_full_pipeline_validation_issue_count": 0,
                "changed_full_pipeline_expected_authoritative_change_fact_count": 3,
                "changed_full_pipeline_expected_formal_api_result_count": 3,
                "changed_full_pipeline_expected_authoritative_member_change_kind_counts": {
                    "implementation_changed": 3,
                },
                "changed_full_pipeline_expected_formal_reachability_status_counts": {
                    "not_found_in_static_analysis": 3,
                },
                "changed_full_pipeline_expected_formal_impact_conclusion_counts": {
                    "inconclusive": 3,
                },
            },
        }
        # This fixture now executes the independent legacy comparator as well,
        # so the relative thresholds have a measured denominator.
        self.assertEqual(evaluate_gate(result, gate)["status"], "passed")
        lost_edge = json.loads(json.dumps(result))
        lost_edge["measurements"]["cold"]["counts"]["edges"] -= 1
        lost_evaluation = evaluate_gate(lost_edge, gate)
        self.assertTrue(any(
            issue["reason_code"] == "BINARY_PERFORMANCE_FACT_CONSERVATION_FAILED"
            and issue["fact_kind"] == "edges"
            for issue in lost_evaluation["issues"]
        ))
        slow_pipeline = json.loads(json.dumps(result))
        slow_pipeline["measurements"]["full_pipeline_probe"][
            "end_to_end_seconds"
        ] = gate["thresholds"]["full_pipeline_end_to_end_seconds"] + 1
        slow_evaluation = evaluate_gate(slow_pipeline, gate)
        self.assertTrue(any(
            issue["reason_code"] == "BINARY_PERFORMANCE_THRESHOLD_EXCEEDED"
            and issue["metric"] == "full_pipeline_end_to_end_seconds"
            for issue in slow_evaluation["issues"]
        ))
        invented_p50 = json.loads(json.dumps(result))
        invented_p50["measurements"]["warm_end_to_end_p50_seconds"] += 1
        p50_evaluation = evaluate_gate(invented_p50, gate)
        self.assertTrue(any(
            issue["reason_code"] == "BINARY_PERFORMANCE_DERIVATION_INVALID"
            and issue["metric"] == "warm_end_to_end_p50_seconds"
            for issue in p50_evaluation["issues"]
        ))
        missing_cpu = json.loads(json.dumps(result))
        del missing_cpu["measurements"]["cold"]["cpu_seconds"]
        cpu_evaluation = evaluate_gate(missing_cpu, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_CPU_MEASUREMENT_INVALID"
            and issue["run"] == "cold"
            for issue in cpu_evaluation["issues"]
        ))
        memory_heavy_pipeline = json.loads(json.dumps(result))
        memory_heavy_pipeline["measurements"]["full_pipeline_probe"][
            "peak_rss_bytes"
        ] = gate["thresholds"]["full_pipeline_peak_rss_bytes"] + 1
        memory_evaluation = evaluate_gate(memory_heavy_pipeline, gate)
        self.assertTrue(any(
            issue["reason_code"] == "BINARY_PERFORMANCE_THRESHOLD_EXCEEDED"
            and issue["metric"] == "full_pipeline_peak_rss_bytes"
            for issue in memory_evaluation["issues"]
        ))
        slow_static = json.loads(json.dumps(result))
        slow_static["measurements"]["full_pipeline_probe"][
            "phase_seconds"
        ]["static_preflight"] = (
            gate["thresholds"]["full_pipeline_phase_seconds"][
                "static_preflight"
            ] + 1
        )
        static_evaluation = evaluate_gate(slow_static, gate)
        self.assertTrue(any(
            issue["reason_code"] == "BINARY_PERFORMANCE_THRESHOLD_EXCEEDED"
            and issue["metric"] == "full_pipeline.static_preflight"
            for issue in static_evaluation["issues"]
        ))
        lost_pipeline_class = json.loads(json.dumps(result))
        lost_pipeline_class["measurements"]["full_pipeline_probe"][
            "current_class_count"
        ] -= 1
        class_evaluation = evaluate_gate(lost_pipeline_class, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_FULL_PIPELINE_CLASS_CONSERVATION_FAILED"
            and issue["side"] == "current"
            for issue in class_evaluation["issues"]
        ))
        invented_change = json.loads(json.dumps(result))
        invented_change["measurements"]["full_pipeline_probe"][
            "authoritative_change_fact_count"
        ] = 1
        change_evaluation = evaluate_gate(invented_change, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH"
            and issue["metric"] == "authoritative_change_fact_count"
            for issue in change_evaluation["issues"]
        ))
        lost_changed_result = json.loads(json.dumps(result))
        lost_changed_result["measurements"]["changed_full_pipeline_probe"][
            "formal_api_result_count"
        ] -= 1
        changed_evaluation = evaluate_gate(lost_changed_result, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH"
            and issue.get("probe") == "changed_full_pipeline_probe"
            and issue["metric"] == "formal_api_result_count"
            for issue in changed_evaluation["issues"]
        ))
        wrong_changed_kind = json.loads(json.dumps(result))
        wrong_changed_kind["measurements"]["changed_full_pipeline_probe"][
            "authoritative_member_change_kind_counts"
        ] = {"contract_changed": 3}
        kind_evaluation = evaluate_gate(wrong_changed_kind, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH"
            and issue.get("probe") == "changed_full_pipeline_probe"
            and issue["metric"]
            == "authoritative_member_change_kind_counts"
            for issue in kind_evaluation["issues"]
        ))
        reparsed_changed = json.loads(json.dumps(result))
        reparsed_changed["measurements"]["changed_full_pipeline_probe"][
            "parser_invocations"
        ] += 1
        cache_evaluation = evaluate_gate(reparsed_changed, gate)
        self.assertTrue(any(
            issue["reason_code"]
            == "BINARY_PERFORMANCE_FULL_PIPELINE_CACHE_MISMATCH"
            and issue.get("probe") == "changed_full_pipeline_probe"
            and issue["metric"] == "parser_invocations"
            for issue in cache_evaluation["issues"]
        ))

        with tempfile.TemporaryDirectory() as output_tmp:
            output = Path(output_tmp) / "result.json"
            gate_path = Path(output_tmp) / "gate.json"
            gate_path.write_text(json.dumps(gate), encoding="utf-8")
            with patch.object(binary_performance_gate, "run_benchmark", return_value=result):
                with redirect_stdout(io.StringIO()):
                    returncode = binary_performance_gate.main([
                        "--output", str(output),
                        "--gate", str(gate_path),
                    ])
            persisted = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(returncode, 0)
        self.assertEqual(persisted["gate_evaluation"]["status"], "passed")

    def test_fixed_dataset_identity_does_not_depend_on_ambient_javac(self):
        with tempfile.TemporaryDirectory() as first_tmp, \
                tempfile.TemporaryDirectory() as second_tmp, patch.object(
                    binary_performance_gate,
                    "run_managed_subprocess",
                    side_effect=AssertionError("ambient toolchain must not run"),
                ):
            first = binary_performance_gate.build_dataset(
                Path(first_tmp), jar_count=2, classes_per_jar=3
            )
            second = binary_performance_gate.build_dataset(
                Path(second_tmp), jar_count=2, classes_per_jar=3
            )

        self.assertEqual(
            [item["sha256"] for item in first],
            [item["sha256"] for item in second],
        )
        self.assertEqual(
            binary_performance_gate._dataset_identity(
                first, classes_per_jar=3
            ),
            binary_performance_gate._dataset_identity(
                second, classes_per_jar=3
            ),
        )
        template = binary_performance_gate._compile_template(Path("unused"))
        self.assertEqual(int.from_bytes(template[6:8], "big"), 52)

    def test_changed_artifact_identity_binds_logical_portable_derivation(self):
        base_identity = "a" * 64
        current_identity = "b" * 64
        identity = (
            binary_performance_gate._changed_artifact_derivation_identity(
                base_artifact_identity=base_identity,
                current_artifact_identity=current_identity,
                classes_per_jar=250,
            )
        )

        self.assertRegex(identity, r"^[0-9a-f]{64}$")
        self.assertEqual(
            identity,
            binary_performance_gate._changed_artifact_derivation_identity(
                base_artifact_identity=base_identity,
                current_artifact_identity=current_identity,
                classes_per_jar=250,
            ),
        )
        alternatives = {
            binary_performance_gate._changed_artifact_derivation_identity(
                base_artifact_identity="c" * 64,
                current_artifact_identity=current_identity,
                classes_per_jar=250,
            ),
            binary_performance_gate._changed_artifact_derivation_identity(
                base_artifact_identity=base_identity,
                current_artifact_identity="d" * 64,
                classes_per_jar=250,
            ),
            binary_performance_gate._changed_artifact_derivation_identity(
                base_artifact_identity=base_identity,
                current_artifact_identity=current_identity,
                classes_per_jar=251,
            ),
        }
        changed_policy = dict(binary_performance_gate._FIXED_ZIP_POLICY)
        changed_policy["compresslevel"] = 2
        with patch.object(
            binary_performance_gate, "_FIXED_ZIP_POLICY", changed_policy,
        ):
            alternatives.add(
                binary_performance_gate._changed_artifact_derivation_identity(
                    base_artifact_identity=base_identity,
                    current_artifact_identity=current_identity,
                    classes_per_jar=250,
                )
            )
        changed_templates = dict(binary_performance_gate._FIXED_TEMPLATE_SHA256)
        changed_templates[2] = "e" * 64
        with patch.object(
            binary_performance_gate,
            "_FIXED_TEMPLATE_SHA256",
            changed_templates,
        ):
            alternatives.add(
                binary_performance_gate._changed_artifact_derivation_identity(
                    base_artifact_identity=base_identity,
                    current_artifact_identity=current_identity,
                    classes_per_jar=250,
                )
            )
        self.assertNotIn(identity, alternatives)
        self.assertEqual(len(alternatives), 5)

    def test_recorded_gate_recomputes_changed_artifact_derivation(self):
        gate = self._currentized_recorded_gate()
        self.assertEqual(
            evaluate_recorded_gate(gate)["status"], "passed"
        )
        gate["measurement_protocol"]["changed_full_pipeline_probe"][
            "logical_artifact_derivation_identity"
        ] = "0" * 64

        evaluation = evaluate_recorded_gate(gate)

        self.assertEqual(evaluation["status"], "failed")
        self.assertTrue(any(
            item.get("reason_code")
            == "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID"
            and item.get("field")
            == (
                "changed_full_pipeline_probe."
                "logical_artifact_derivation_identity"
            )
            for item in evaluation["issues"]
        ))

    def test_benchmark_and_pipeline_generation_source_identities_match(self):
        import binary_pipeline
        from binary_performance_identity import generation_source_identity

        records = binary_pipeline._verify_captured_generation_sources()
        self.assertEqual(
            binary_performance_gate._generation_source_identity(),
            generation_source_identity(records),
        )

    def test_generation_identity_ignores_private_support_snapshot_basename(self):
        import binary_pipeline
        from binary_performance_identity import generation_source_identity

        original_support = binary_pipeline.SUPPORT_MANIFEST_PATH
        with tempfile.TemporaryDirectory() as tmp:
            private_support = Path(tmp) / "support_manifest.json"
            private_support.write_bytes(original_support.read_bytes())
            with patch.object(
                binary_pipeline, "SUPPORT_MANIFEST_PATH", private_support
            ):
                records = binary_pipeline._verify_captured_generation_sources()
                self.assertEqual(
                    binary_performance_gate._generation_source_identity(),
                    generation_source_identity(records),
                )

    def test_recapture_preflight_accepts_relocated_support_snapshot(self):
        provisional, implementation = self._synthetic_current_provisional()

        with tempfile.TemporaryDirectory() as tmp:
            provisional_path = Path(tmp) / "provisional.json"
            provisional_path.write_text(
                json.dumps(provisional, ensure_ascii=False, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            binary_performance_gate._preflight_performance_authority(
                implementation,
                provisional_gate_path=provisional_path,
            )

    def test_small_recapture_probe_closes_real_pipeline(self):
        provisional, implementation = self._synthetic_current_provisional()
        asm_jar = binary_asm_helper.resolve_asm_jar()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifacts = binary_performance_gate.build_dataset(
                root / "dataset", jar_count=1, classes_per_jar=1
            )
            provisional_path = root / "provisional.json"
            provisional_path.write_text(
                json.dumps(provisional, ensure_ascii=False, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            result = (
                binary_performance_gate._run_isolated_full_pipeline_probe(
                    artifacts,
                    root=root / "recapture-probe",
                    asm_jar=asm_jar,
                    classes_per_jar=1,
                    expected_implementation=implementation,
                    provisional_gate_path=provisional_path,
                )
            )

        self.assertEqual(
            result["performance_authority_mode"],
            "release_recapture_measurement",
        )
        self.assertEqual(result["validation_status"], "passed")
        self.assertEqual(result["validation_issue_count"], 0)
        self.assertTrue(result["activation_recapture_discarded"])
        self.assertTrue(result["active_generation_absent"])
        self.assertTrue(result["pending_generation_absent"])
        self.assertTrue(result["validation_checkpoint_absent"])

    def test_runtime_implementation_identity_binds_jdk_preflight(self):
        asm_jar = binary_asm_helper.resolve_asm_jar()
        implementation = (
            binary_performance_gate._performance_implementation_protocol(asm_jar)
        )
        self.assertRegex(
            implementation["jdk_preflight_identity"], r"^[0-9a-f]{64}$"
        )
        changed = dict(implementation)
        changed["jdk_preflight_identity"] = "f" * 64
        self.assertNotEqual(
            binary_performance_gate._runtime_implementation_identity(
                implementation
            ),
            binary_performance_gate._runtime_implementation_identity(changed),
        )

    def test_live_runtime_identity_reuses_exact_verified_generation_records(self):
        import binary_pipeline

        asm_jar = binary_asm_helper.resolve_asm_jar()
        records = binary_pipeline._verify_captured_generation_sources()
        independent = (
            binary_performance_gate._performance_implementation_protocol(
                asm_jar
            )
        )
        with patch.object(
            binary_performance_gate,
            "_generation_source_identity",
            side_effect=AssertionError(
                "verified generation records must not be re-hashed"
            ),
        ), patch.object(
            binary_pipeline,
            "_resume_generation_source_records",
            side_effect=AssertionError(
                "runtime identity must reuse the same verified records"
            ),
        ):
            reused = (
                binary_performance_gate._performance_implementation_protocol(
                    asm_jar,
                    _verified_generation_source_records=records,
                )
            )

        self.assertEqual(reused, independent)

    def test_live_recapture_binding_collects_generation_sources_once(self):
        import binary_pipeline

        provisional, implementation = self._synthetic_current_provisional()
        original_collect = (
            binary_pipeline._verify_captured_generation_sources
        )
        original_resume_records = (
            binary_pipeline._resume_generation_source_records
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provisional_path = root / "provisional.json"
            provisional_path.write_text(
                json.dumps(provisional, ensure_ascii=False, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            with binary_performance_gate._candidate_performance_authority(
                root / "authority",
                implementation,
                provisional_gate_path=provisional_path,
            ):
                support = binary_pipeline._load_support_manifest_snapshot()
                captured = binary_pipeline._performance_authority_gate_binding(
                    support
                )
                with patch.object(
                    binary_pipeline,
                    "_verify_captured_generation_sources",
                    wraps=original_collect,
                ) as collect, patch.object(
                    binary_pipeline,
                    "_resume_generation_source_records",
                    wraps=original_resume_records,
                ) as resume_records, patch.object(
                    binary_performance_gate,
                    "_generation_source_identity",
                    side_effect=AssertionError(
                        "live verification must reuse its fresh records"
                    ),
                ):
                    current = (
                        binary_pipeline
                        ._verify_performance_authority_gate_binding(captured)
                    )

        self.assertEqual(current, captured)
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(resume_records.call_count, 1)

    def test_runtime_record_reuse_mode_rejects_boolean_aliases(self):
        import binary_pipeline

        for invalid in (0, 1, "true", None):
            with self.subTest(value=invalid), self.assertRaises(
                binary_pipeline.BinaryPipelineError
            ) as raised:
                binary_pipeline._performance_authority_gate_binding(
                    {},
                    reuse_verified_generation_records_for_runtime=invalid,
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_PERFORMANCE_AUTHORITY_BINDING_INVALID",
            )

    def test_candidate_authority_is_context_local_and_never_release_evidence(self):
        import binary_pipeline

        implementation = (
            binary_performance_gate._performance_implementation_protocol(
                include_runtime=False
            )
        )
        original_gate = binary_pipeline.PERFORMANCE_GATE_PATH
        original_support = binary_pipeline.SUPPORT_MANIFEST_PATH
        candidate_gate = None
        candidate_support = None
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                binary_pipeline,
                "_performance_authority_gate_binding",
                return_value={"authority_mode": "candidate_source_measurement"},
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "injected context failure"
                ):
                    with binary_performance_gate._candidate_performance_authority(
                        Path(tmp), implementation
                    ) as mode:
                        self.assertEqual(mode, "candidate_source_measurement")
                        candidate_gate = binary_pipeline.PERFORMANCE_GATE_PATH
                        candidate_support = binary_pipeline.SUPPORT_MANIFEST_PATH
                        self.assertIs(
                            binary_pipeline
                            ._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.get(),
                            binary_pipeline
                            ._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY,
                        )
                        raise RuntimeError("injected context failure")

            self.assertEqual(binary_pipeline.PERFORMANCE_GATE_PATH, original_gate)
            self.assertEqual(
                binary_pipeline.SUPPORT_MANIFEST_PATH, original_support
            )
            self.assertIsNone(
                binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT.get()
            )
            support = json.loads(candidate_support.read_text(encoding="utf-8"))
            with patch.object(
                binary_pipeline, "PERFORMANCE_GATE_PATH", candidate_gate
            ), patch.object(
                binary_pipeline, "SUPPORT_MANIFEST_PATH", candidate_support
            ), self.assertRaises(binary_pipeline.BinaryPipelineError) as raised:
                binary_pipeline._performance_authority_gate_binding(
                    support,
                    generation_source_records=(
                        binary_pipeline._verify_captured_generation_sources()
                    ),
                )
            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_PERFORMANCE_MEASUREMENT_BOOTSTRAP_FORBIDDEN",
            )

    def test_recapture_authority_preserves_exact_provisional_bytes(self):
        import binary_pipeline

        provisional_content = (
            b'{\n  "schema" : "synthetic-provisional",\n'
            b'  "nested" : { "value" : 1 }\n}\n'
        )
        implementation = {"source_implementation_identity": "a" * 64}
        observed = {}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "probe"
            provisional = Path(tmp) / "provisional.json"
            support = Path(tmp) / "support.json"
            original_gate = Path(tmp) / "recorded.json"
            provisional.write_bytes(provisional_content)
            support.write_text(
                json.dumps({"performance_gate": {}}) + "\n",
                encoding="utf-8",
            )
            original_gate.write_text("{}\n", encoding="utf-8")

            def observe_binding(_support):
                copied = binary_pipeline.PERFORMANCE_GATE_PATH.read_bytes()
                observed["content"] = copied
                observed["sha256"] = hashlib.sha256(copied).hexdigest()
                return {"authority_mode": "release_recapture_measurement"}

            with patch.object(
                binary_pipeline, "PERFORMANCE_GATE_PATH", original_gate
            ), patch.object(
                binary_pipeline, "SUPPORT_MANIFEST_PATH", support
            ), patch.object(
                binary_pipeline,
                "_performance_authority_gate_binding",
                side_effect=observe_binding,
            ), patch.object(
                binary_pipeline,
                "_cleanup_performance_recapture_state",
            ), patch.object(
                binary_performance_gate,
                "evaluate_provisional_gate",
                return_value={"status": "passed", "issues": []},
            ):
                with binary_performance_gate._candidate_performance_authority(
                    root,
                    implementation,
                    provisional_gate_path=provisional,
                ) as mode:
                    self.assertEqual(mode, "release_recapture_measurement")
                    self.assertEqual(
                        binary_pipeline.PERFORMANCE_GATE_PATH.read_bytes(),
                        provisional_content,
                    )

        self.assertEqual(observed["content"], provisional_content)
        self.assertEqual(
            observed["sha256"], hashlib.sha256(provisional_content).hexdigest()
        )

    def test_captured_at_requires_canonical_utc_rfc3339(self):
        self.assertTrue(
            binary_performance_gate._is_canonical_utc_captured_at(
                "2026-08-13T12:34:56Z"
            )
        )
        for invalid in (
            "2026-08-13",
            "2026-02-30T00:00:00Z",
            "2026-08-13T12:34:56+00:00",
            "2026-08-13T12:34:56.000Z",
            "label",
            True,
        ):
            with self.subTest(value=invalid):
                self.assertFalse(
                    binary_performance_gate._is_canonical_utc_captured_at(
                        invalid
                    )
                )

    def test_recorded_gate_rejects_noncanonical_capture_timestamp(self):
        gate = self._currentized_recorded_gate()
        gate["recorded_measurements"]["captured_at"] = "2026-08-13"
        for name in ("full_pipeline_probe", "changed_full_pipeline_probe"):
            gate["recorded_measurements"][name]["captured_at"] = "2026-08-13"

        evaluation = evaluate_recorded_gate(gate)

        self.assertEqual(evaluation["status"], "failed")
        self.assertTrue(any(
            issue.get("field") == "recorded_measurements.captured_at"
            for issue in evaluation["issues"]
        ), evaluation["issues"])

    def test_production_authority_requires_formal_recorded_replay(self):
        import binary_pipeline

        records = binary_pipeline._verify_captured_generation_sources()
        current = (
            binary_performance_gate._performance_implementation_protocol(
                include_runtime=False
            )
        )
        fixture_root = (
            ROOT_DIR / "tests" / "fixtures" / "binary_first"
        )
        evidence = json.loads(
            (fixture_root / "performance_gate.json").read_text(
                encoding="utf-8"
            )
        )
        support = json.loads(
            binary_pipeline.SUPPORT_MANIFEST_PATH.read_text(encoding="utf-8")
        )
        protocol = dict(evidence["measurement_protocol"])
        protocol["implementation"] = {
            **dict(protocol.get("implementation") or {}),
            **current,
        }
        protocol["source_implementation_identity"] = current[
            "source_implementation_identity"
        ]
        evidence["measurement_protocol"] = protocol

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_path = root / "performance_gate.json"
            evidence_path.write_text(
                json.dumps(evidence, sort_keys=True), encoding="utf-8"
            )
            candidate_support = dict(support)
            performance = dict(candidate_support["performance_gate"])
            performance.update({
                "status": "passed",
                "path": binary_pipeline.PERFORMANCE_GATE_CONTRACT_PATH,
                "sha256": binary_performance_gate._sha256(evidence_path),
                "source_implementation_identity": current[
                    "source_implementation_identity"
                ],
                "warm_parser_invocations": 0,
                "blocks_binary_authority_switch": False,
            })
            candidate_support["performance_gate"] = performance

            failed_replay = {
                "status": "failed",
                "issues": [{
                    "reason_code": "BINARY_PERFORMANCE_TEST_REPLAY_FAILED"
                }],
            }
            with patch.object(
                binary_pipeline, "PERFORMANCE_GATE_PATH", evidence_path,
            ), patch.object(
                binary_performance_gate,
                "evaluate_recorded_gate",
                return_value=failed_replay,
            ) as verifier, self.assertRaises(
                binary_pipeline.BinaryPipelineError
            ) as failure:
                binary_pipeline._performance_authority_gate_binding(
                    candidate_support,
                    generation_source_records=records,
                )
            self.assertEqual(
                failure.exception.reason_code,
                "BINARY_PERFORMANCE_RECORDED_EVIDENCE_INVALID",
            )
            supplied = verifier.call_args.kwargs[
                "_current_source_implementation"
            ]
            self.assertEqual(supplied, current)

            with patch.object(
                binary_pipeline, "PERFORMANCE_GATE_PATH", evidence_path,
            ), patch.object(
                binary_performance_gate,
                "evaluate_recorded_gate",
                return_value={"status": "passed", "issues": []},
            ) as verifier:
                binding = binary_pipeline._performance_authority_gate_binding(
                    candidate_support,
                    generation_source_records=records,
                )
            self.assertTrue(
                binary_pipeline._performance_authority_binding_is_valid(
                    binding
                )
            )
            verifier.assert_called_once()

    def test_production_authority_rejects_tampered_measurement_with_new_sha(self):
        import binary_pipeline

        records = binary_pipeline._verify_captured_generation_sources()
        evidence = self._currentized_recorded_gate()
        current_source_identity = evidence["measurement_protocol"][
            "source_implementation_identity"
        ]
        support = json.loads(
            binary_pipeline.SUPPORT_MANIFEST_PATH.read_text(encoding="utf-8")
        )

        with tempfile.TemporaryDirectory() as tmp:
            evidence_path = Path(tmp) / "performance_gate.json"

            def write_and_bind(value):
                evidence_path.write_text(
                    json.dumps(value, sort_keys=True), encoding="utf-8"
                )
                rebound_support = json.loads(json.dumps(support))
                rebound_support["performance_gate"].update({
                    "status": "passed",
                    "path": binary_pipeline.PERFORMANCE_GATE_CONTRACT_PATH,
                    "sha256": binary_performance_gate._sha256(evidence_path),
                    "source_implementation_identity": (
                        current_source_identity
                    ),
                    "warm_parser_invocations": 0,
                    "blocks_binary_authority_switch": False,
                })
                return rebound_support

            valid_support = write_and_bind(evidence)
            with patch.object(
                binary_pipeline, "PERFORMANCE_GATE_PATH", evidence_path,
            ):
                valid_binding = (
                    binary_pipeline._performance_authority_gate_binding(
                        valid_support,
                        generation_source_records=records,
                    )
                )
            self.assertTrue(
                binary_pipeline._performance_authority_binding_is_valid(
                    valid_binding
                )
            )

            tampered = json.loads(json.dumps(evidence))
            tampered["recorded_measurements"][
                "warm_end_to_end_p50_seconds"
            ] = 0
            tampered_support = write_and_bind(tampered)
            self.assertEqual(
                tampered_support["performance_gate"]["sha256"],
                binary_performance_gate._sha256(evidence_path),
            )
            with patch.object(
                binary_pipeline, "PERFORMANCE_GATE_PATH", evidence_path,
            ), self.assertRaises(
                binary_pipeline.BinaryPipelineError
            ) as failure:
                binary_pipeline._performance_authority_gate_binding(
                    tampered_support,
                    generation_source_records=records,
                )

        self.assertEqual(
            failure.exception.reason_code,
            "BINARY_PERFORMANCE_RECORDED_EVIDENCE_INVALID",
        )
        self.assertIn("warm_p50", str(failure.exception))

    def test_probe_worker_preserves_structured_failure(self):
        implementation = {
            "generation_source_identity": "1" * 64,
            "validator_source_identity": "2" * 64,
            "oracle_support_manifest_identity": "3" * 64,
            "harness_source_identity": "4" * 64,
            "pipeline_generation_implementation_identity": "5" * 64,
            "validator_implementation_identity": "6" * 64,
            "jdk_preflight_identity": "7" * 64,
        }
        implementation["source_implementation_identity"] = (
            binary_performance_gate._source_implementation_identity(
                implementation
            )
        )
        implementation["runtime_implementation_identity"] = (
            binary_performance_gate._runtime_implementation_identity(
                implementation
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worker_input = root / "input.json"
            worker_output = root / "output.json"
            asm_jar = root / "asm.jar"
            asm_jar.write_bytes(b"asm")
            artifact_path = root / "artifact-0000.jar"
            artifact_path.write_bytes(b"artifact")
            artifact = {
                "path": str(artifact_path.resolve()),
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
                "byte_length": artifact_path.stat().st_size,
                "jar_index": 0,
                "first_class_index": 0,
                "class_count": 1,
            }
            worker_input.write_text(json.dumps({
                "schema": binary_performance_gate.PROBE_WORKER_SCHEMA,
                "artifacts": [artifact],
                "current_artifacts": None,
                "asm_jar": str(asm_jar.resolve()),
                "classes_per_jar": 1,
                "expected_implementation": implementation,
                "provisional_gate_path": "",
            }), encoding="utf-8")
            with patch.object(
                binary_performance_gate,
                "_performance_implementation_protocol",
                return_value=implementation,
            ), patch.object(
                binary_performance_gate,
                "_candidate_performance_authority",
                return_value=nullcontext("candidate_source_measurement"),
            ), patch.object(
                binary_performance_gate,
                "_full_pipeline_probe",
                side_effect=binary_performance_gate.PerformanceGateError(
                    "injected probe failure"
                ),
            ):
                returncode = binary_performance_gate._run_probe_worker(
                    worker_input, worker_output
                )
            response = json.loads(worker_output.read_text(encoding="utf-8"))

        self.assertEqual(returncode, 1)
        self.assertEqual(response["status"], "failed")
        self.assertEqual(
            response["failure"]["reason_code"],
            "BINARY_PERFORMANCE_FULL_PIPELINE_PROBE_FAILED",
        )
        self.assertIn("injected probe failure", response["failure"]["detail"])

    def test_checked_in_release_measurements_are_replayed_not_self_attested(self):
        gate = self._currentized_recorded_gate()

        evaluation = evaluate_recorded_gate(gate)

        self.assertEqual(evaluation["status"], "passed", evaluation["issues"])
        self.assertEqual(evaluation["jar_count"], 400)
        self.assertEqual(evaluation["class_count"], 100000)
        self.assertEqual(evaluation["changed_class_count"], 250)
        self.assertTrue(evaluation["recorded_measurements_replayed"])
        self.assertEqual(
            gate["recorded_measurements"]["warm_end_to_end_p50_seconds"],
            binary_performance_gate._p50(
                gate["recorded_measurements"][
                    "warm_end_to_end_samples_seconds"
                ]
            ),
        )

        corrupted_p50 = json.loads(json.dumps(gate))
        corrupted_p50["recorded_measurements"][
            "warm_end_to_end_p50_seconds"
        ] = 0
        p50_evaluation = evaluate_recorded_gate(corrupted_p50)
        self.assertEqual(p50_evaluation["status"], "failed")
        self.assertTrue(any(
            item.get("field") == "warm_p50"
            for item in p50_evaluation["issues"]
        ))

        corrupted_cpu = json.loads(json.dumps(gate))
        corrupted_cpu["recorded_measurements"]["cold_cpu_seconds"] = 0
        cpu_evaluation = evaluate_recorded_gate(corrupted_cpu)
        self.assertEqual(cpu_evaluation["status"], "failed")
        self.assertTrue(any(
            item["reason_code"] == "BINARY_PERFORMANCE_RECORDED_CPU_INVALID"
            and item.get("field") == "cold"
            for item in cpu_evaluation["issues"]
        ))

        corrupted = json.loads(json.dumps(gate))
        corrupted["recorded_measurements"]["class_count"] -= 1
        corrupted_evaluation = evaluate_recorded_gate(corrupted)
        self.assertEqual(corrupted_evaluation["status"], "failed")
        self.assertIn(
            "BINARY_PERFORMANCE_RECORDED_CONSERVATION_INVALID",
            {item["reason_code"] for item in corrupted_evaluation["issues"]},
        )

        self_attested = json.loads(json.dumps(gate))
        self_attested["recorded_measurements"]["changed_full_pipeline_probe"][
            "formal_api_result_count"
        ] = 249
        self.assertEqual(
            evaluate_recorded_gate(self_attested)["status"], "failed"
        )

        bootstrap = json.loads(json.dumps(gate))
        bootstrap["measurement_bootstrap"] = {
            "mode": "candidate_source_measurement",
            "not_release_evidence": True,
        }
        bootstrap_evaluation = evaluate_recorded_gate(bootstrap)
        self.assertEqual(bootstrap_evaluation["status"], "failed")
        self.assertEqual(
            bootstrap_evaluation["issues"][0]["reason_code"],
            "BINARY_PERFORMANCE_RECORDED_BOOTSTRAP_FORBIDDEN",
        )

        damaged_dataset = json.loads(json.dumps(gate))
        damaged_dataset["measurement_protocol"][
            "dataset_artifact_identities"
        ] = damaged_dataset["measurement_protocol"].get(
            "dataset_artifact_identities", []
        )[:-1]
        dataset_evaluation = evaluate_recorded_gate(damaged_dataset)
        self.assertEqual(dataset_evaluation["status"], "failed")
        self.assertIn(
            "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
            {item["reason_code"] for item in dataset_evaluation["issues"]},
        )

    def test_recorded_gate_malformed_shapes_fail_closed_without_exception(self):
        cases = (
            [],
            "not-an-object",
            {"measurement_protocol": []},
            {"measurement_protocol": {}, "recorded_measurements": "x"},
            {
                "measurement_protocol": {
                    "sample_runs": "x",
                    "full_pipeline_probe": [],
                },
                "recorded_measurements": {},
            },
            {"recorded_measurements": {"peak_rss_bytes": float("nan")}},
            {"measurement_protocol": {"dataset_artifact_identities": "x"}},
        )
        for value in cases:
            with self.subTest(value=value):
                result = evaluate_recorded_gate(value)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["issue_count"], 1)
                self.assertFalse(result["recorded_measurements_replayed"])
                self.assertIn(
                    result["issues"][0]["reason_code"],
                    {
                        "BINARY_PERFORMANCE_RECORDED_ROOT_INVALID",
                        "BINARY_PERFORMANCE_RECORDED_STRUCTURE_INVALID",
                        "BINARY_PERFORMANCE_RECORDED_NONFINITE_NUMBER",
                    },
                )

    def test_full_pipeline_probe_uses_every_artifact_by_default(self):
        artifacts = [
            {"path": f"/fixture/artifact-{index:04d}.jar"}
            for index in range(25)
        ]
        pipeline_result = {
            "total_elapsed_seconds": 1.25,
            "total_elapsed_scope": "current_pipeline_attempt",
            "phase_timings_scope": "current_pipeline_attempt",
            "phase_timings": [
                {
                    "phase": "independent_validation",
                    "elapsed_seconds": 0.5,
                    "peak_rss_bytes": 1024,
                },
                {
                    "phase": "validated_generation_activation",
                    "elapsed_seconds": 0.01,
                    "peak_rss_bytes": 1024,
                    "activation_authority_mode": (
                        "candidate_source_measurement"
                    ),
                    "publication_deferred": False,
                    "checkpoint_retained": False,
                    "activation_candidate_discarded": True,
                },
            ],
            "peak_rss_bytes": 1024,
            "cache_metrics": {
                "classfile_parser_invocations": 25,
                "artifact_snapshot_hits": 0,
            },
        }
        evidence = {
            "class_count": 75,
            "base_class_count": 75,
            "current_class_count": 75,
            "validation_status": "passed",
            "validation_issue_count": 0,
            "authoritative_change_fact_count": 0,
            "formal_api_result_count": 0,
        }
        def fake_pipeline(_config, *, output_root, **_kwargs):
            Path(output_root).mkdir(parents=True)
            return pipeline_result

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_performance_gate, "_jdk_home", return_value=Path("/jdk")
        ), patch.object(
            binary_performance_gate,
            "_full_pipeline_evidence",
            return_value=evidence,
        ), patch(
            "binary_pipeline.run_pipeline", side_effect=fake_pipeline
        ) as run_pipeline:
            result = binary_performance_gate._full_pipeline_probe(
                artifacts,
                root=Path(tmp),
                asm_jar=Path("/asm.jar"),
                classes_per_jar=3,
            )

        submitted = run_pipeline.call_args.args[0]
        self.assertEqual(len(submitted["base"]["artifacts"]), 25)
        self.assertEqual(len(submitted["current"]["artifacts"]), 25)
        self.assertEqual(result["jar_count"], 25)
        self.assertEqual(result["class_count"], 75)

    def test_full_pipeline_probe_routes_nonidentical_current_side(self):
        base = [
            {"path": "/fixture/base-0.jar", "sha256": "a" * 64},
            {"path": "/fixture/shared-1.jar", "sha256": "b" * 64},
        ]
        current = [
            {"path": "/fixture/current-0.jar", "sha256": "c" * 64},
            {"path": "/fixture/shared-1.jar", "sha256": "b" * 64},
        ]
        pipeline_result = {
            "total_elapsed_seconds": 2.5,
            "total_elapsed_scope": "current_pipeline_attempt",
            "phase_timings_scope": "current_pipeline_attempt",
            "phase_timings": [{
                "phase": "validated_generation_activation",
                "elapsed_seconds": 0.01,
                "peak_rss_bytes": 2048,
                "activation_authority_mode": "candidate_source_measurement",
                "publication_deferred": False,
                "checkpoint_retained": False,
                "activation_candidate_discarded": True,
            }],
            "peak_rss_bytes": 2048,
            "cache_metrics": {
                "classfile_parser_invocations": 3,
                "artifact_snapshot_hits": 1,
            },
        }
        evidence = {
            "class_count": 6,
            "base_class_count": 6,
            "current_class_count": 6,
            "validation_status": "passed",
            "validation_issue_count": 0,
            "authoritative_change_fact_count": 3,
            "formal_api_result_count": 3,
        }
        def fake_pipeline(_config, *, output_root, **_kwargs):
            Path(output_root).mkdir(parents=True)
            return pipeline_result

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_performance_gate, "_jdk_home", return_value=Path("/jdk")
        ), patch.object(
            binary_performance_gate,
            "_full_pipeline_evidence",
            return_value=evidence,
        ), patch(
            "binary_pipeline.run_pipeline", side_effect=fake_pipeline
        ) as run_pipeline:
            result = binary_performance_gate._full_pipeline_probe(
                base,
                current_artifacts=current,
                root=Path(tmp),
                asm_jar=Path("/asm.jar"),
                classes_per_jar=3,
            )

        submitted = run_pipeline.call_args.args[0]
        self.assertEqual(
            submitted["base"]["artifacts"][0]["path"], "/fixture/base-0.jar"
        )
        self.assertEqual(
            submitted["current"]["artifacts"][0]["path"],
            "/fixture/current-0.jar",
        )
        self.assertEqual(
            result["comparison"], "nonidentical-base-current-cold-output"
        )
        self.assertEqual(result["authoritative_change_fact_count"], 3)
        self.assertEqual(result["formal_api_result_count"], 3)


if __name__ == "__main__":
    unittest.main()
