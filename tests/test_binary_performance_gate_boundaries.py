import argparse
import io
import math
import os
import stat
import sys
import tempfile
import unittest
from copy import deepcopy
from contextlib import closing, nullcontext, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_performance_gate as gate  # noqa: E402


class BinaryPerformanceGateBoundaryTest(unittest.TestCase):
    @staticmethod
    def stat_result(
        *, mode=stat.S_IFREG | 0o600, device=1, inode=2,
        links=1, size=3, modified_ns=4,
    ):
        return SimpleNamespace(
            st_mode=mode,
            st_dev=device,
            st_ino=inode,
            st_nlink=links,
            st_size=size,
            st_mtime=modified_ns / 1_000_000_000,
            st_mtime_ns=modified_ns,
        )

    @staticmethod
    def implementation():
        value = {
            "generation_source_identity": "1" * 64,
            "validator_source_identity": "2" * 64,
            "oracle_support_manifest_identity": "3" * 64,
            "harness_source_identity": "4" * 64,
            "pipeline_generation_implementation_identity": "5" * 64,
            "validator_implementation_identity": "6" * 64,
            "jdk_preflight_identity": "7" * 64,
        }
        value["source_implementation_identity"] = (
            gate._source_implementation_identity(value)
        )
        value["runtime_implementation_identity"] = (
            gate._runtime_implementation_identity(value)
        )
        return value

    @staticmethod
    def valid_probe_result(*, expected_mode=None):
        mode = expected_mode or gate._CANDIDATE_PROBE_AUTHORITY_MODE
        phase_seconds = {name: 0.01 for name in gate.FULL_PIPELINE_PHASES}
        phase_peaks = {
            name: index + 1
            for index, name in enumerate(gate.FULL_PIPELINE_PHASES)
        }
        return {
            "status": "passed",
            "comparison": "identical-base-current-cold-output",
            "rss_measurement_scope": (
                "dedicated_probe_process_and_completed_children"
            ),
            "pipeline_total_elapsed_scope": "current_pipeline_attempt",
            "pipeline_phase_timings_scope": "current_pipeline_attempt",
            "activation_authority_mode": mode,
            "validation_status": "passed",
            "jar_count": 1,
            "current_jar_count": 1,
            "expected_class_count": 2,
            "class_count": 2,
            "base_class_count": 2,
            "current_class_count": 2,
            "validation_issue_count": 0,
            "publication_deferred": False,
            "checkpoint_retained": False,
            "active_generation_absent": True,
            "pending_generation_absent": True,
            "validation_checkpoint_absent": True,
            "activation_candidate_discarded": (
                mode == gate._CANDIDATE_PROBE_AUTHORITY_MODE
            ),
            "activation_recapture_discarded": (
                mode == gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE
            ),
            "phase_seconds": phase_seconds,
            "pipeline_reported_seconds": 1.0,
            "end_to_end_seconds": 2.0,
            "post_pipeline_peak_rss_bytes": 10,
            "phase_peak_rss_bytes": phase_peaks,
            "peak_rss_bytes": 10,
            "pipeline_reported_peak_rss_bytes": 9,
            "artifact_snapshot_hits": 0,
            "artifact_snapshot_disk_hits": 0,
            "artifact_snapshot_memory_hits": 0,
            "parser_invocations": 1,
            "authoritative_member_change_kind_counts": {},
            "authoritative_change_fact_count": 0,
            "formal_reachability_status_counts": {},
            "formal_impact_conclusion_counts": {},
            "formal_api_result_count": 0,
        }

    @staticmethod
    def authority_binding(source_identity, *, mode=None, salt="a"):
        authority_mode = mode or gate._CANDIDATE_PROBE_AUTHORITY_MODE
        value = {
            "schema": "java-upgrade-analyzer.performance-authority-binding.v2",
            "authority_mode": authority_mode,
            "support_contract_identity": salt * 64,
            "evidence_sha256": chr(ord(salt) + 1) * 64,
            "source_implementation_identity": source_identity,
        }
        value["binding_identity"] = gate.canonical_identity(
            "binary_performance_authority_binding_identity",
            {
                "support_contract_identity": value["support_contract_identity"],
                "evidence_sha256": value["evidence_sha256"],
                "source_implementation_identity": source_identity,
                "authority_mode": authority_mode,
            },
            schema_version="1",
        )
        return value

    @staticmethod
    def valid_analysis_run():
        return {
            "end_to_end_seconds": 10.0,
            "cpu_seconds": 5.0,
            "average_cpu_cores": 0.5,
            "stage_seconds": {
                name: 1.0 for name in gate._RAW_STAGE_FIELDS
            },
            "parser_invocations": 1,
            "cache_hits": 0,
            "counts": {
                "entries": 10,
                "classes": 10,
                "members": 20,
                "edges": 20,
                "resources": 0,
            },
            "inventory": {"entry_count": 10, "uncompressed_bytes": 100},
            "overlay_status": "not_provided",
            "report_bytes": 100,
            "db_bytes": 100,
            "cache_bytes": 100,
            "peak_rss_bytes": 100,
            "bytes_per_class": 20.0,
            "bytes_per_edge": 5.0,
        }

    @classmethod
    def valid_raw_probe(cls, *, mode=None, source_identity=None):
        authority_mode = mode or gate._CANDIDATE_PROBE_AUTHORITY_MODE
        source = source_identity or cls.implementation()[
            "source_implementation_identity"
        ]
        value = cls.valid_probe_result(expected_mode=authority_mode)
        value.update({
            "performance_authority_mode": authority_mode,
            "process_id": 1,
            "cpu_seconds": 1.0,
            "average_cpu_cores": 0.5,
            "pipeline_performance_authority_binding": cls.authority_binding(
                source, mode=authority_mode,
            ),
        })
        return value

    @classmethod
    def valid_raw_release_result(cls, *, mode=None):
        authority_mode = mode or gate._CANDIDATE_PROBE_AUTHORITY_MODE
        implementation = cls.implementation()
        protocol = {name: None for name in gate._MEASUREMENT_PROTOCOL_FIELDS}
        protocol.update({
            "implementation": implementation,
            "source_implementation_identity": implementation[
                "source_implementation_identity"
            ],
            "runtime_implementation_identity": implementation[
                "runtime_implementation_identity"
            ],
            "sample_runs": {"warm": 1},
        })
        warmup = cls.valid_analysis_run()
        cold = cls.valid_analysis_run()
        warm = cls.valid_analysis_run()
        legacy = {
            "end_to_end_seconds": 2.0,
            "cpu_seconds": 1.0,
            "average_cpu_cores": 0.5,
            "class_count": 10,
            "peak_rss_bytes": 100,
            "implementation": "legacy-javap-c-s-p-batched-per-artifact",
        }
        full = cls.valid_raw_probe(
            mode=authority_mode,
            source_identity=implementation["source_implementation_identity"],
        )
        changed = deepcopy(full)
        measured_runs = [cold, warm, legacy, full, changed]
        total_wall = sum(item["end_to_end_seconds"] for item in measured_runs)
        total_cpu = sum(item["cpu_seconds"] for item in measured_runs)
        measurements = {
            "warmup": warmup,
            "cold": cold,
            "warm_runs": [warm],
            "warm_end_to_end_p50_seconds": warm["end_to_end_seconds"],
            "warm_end_to_end_p95_seconds": warm["end_to_end_seconds"],
            "legacy": legacy,
            "full_pipeline_probe": full,
            "changed_full_pipeline_probe": changed,
            "cold_relative_legacy_ratio": (
                cold["end_to_end_seconds"] / legacy["end_to_end_seconds"]
            ),
            "peak_rss_bytes": 100,
            "disk_bytes": cold["db_bytes"] + cold["cache_bytes"],
            "total_measured_wall_seconds": total_wall,
            "total_measured_cpu_seconds": total_cpu,
            "average_cpu_cores": total_cpu / total_wall,
        }
        return {
            "schema": gate.SCHEMA,
            "status": "measured",
            "measurement_protocol": protocol,
            "measurements": measurements,
        }

    @classmethod
    def valid_gate_evaluation_pair(cls):
        result = cls.valid_raw_release_result()
        protocol = result["measurement_protocol"]
        protocol.update({
            "machine_identity": "machine",
            "dataset_identity": "d" * 64,
            "jar_count": 1,
            "class_count": 10,
            "cpu_time_source": "resource",
            "full_pipeline_probe": {
                "jar_count": 1,
                "class_count": 2,
                "comparison": "identical",
                "process_isolation": True,
                "includes": list(gate.FULL_PIPELINE_PHASES),
            },
            "changed_full_pipeline_probe": {
                "jar_count": 1,
                "class_count": 2,
                "comparison": "changed",
                "changed_jar_count": 1,
                "changed_class_count": 2,
                "current_artifact_identity": "e" * 64,
                "logical_artifact_derivation_identity": "f" * 64,
                "process_isolation": True,
                "includes": list(gate.FULL_PIPELINE_PHASES),
            },
        })
        thresholds = {
            "cold_end_to_end_seconds": 11.0,
            "warm_end_to_end_p50_seconds": 11.0,
            "warm_end_to_end_p95_seconds": 11.0,
            "peak_rss_bytes": 101,
            "disk_bytes": 201,
            "bytes_per_class": 21.0,
            "bytes_per_edge": 6.0,
            "cold_relative_legacy_ratio": 6.0,
            "warm_relative_legacy_ratio": 6.0,
            "full_pipeline_end_to_end_seconds": 3.0,
            "full_pipeline_peak_rss_bytes": 11,
            "full_pipeline_phase_seconds": {
                name: 0.02 for name in gate.FULL_PIPELINE_PHASES
            },
            "changed_full_pipeline_end_to_end_seconds": 3.0,
            "changed_full_pipeline_peak_rss_bytes": 11,
            "changed_full_pipeline_phase_seconds": {
                name: 0.02 for name in gate.FULL_PIPELINE_PHASES
            },
            "stage_p95_seconds": {
                name: 2.0 for name in gate._RAW_STAGE_FIELDS
            },
        }
        invariants = {
            "expected_class_count": 10,
            "expected_member_count": 20,
            "expected_edge_count": 20,
            "warm_parser_invocations": 1,
            "full_pipeline_expected_class_count": 2,
            "full_pipeline_expected_parser_invocations": 1,
            "full_pipeline_expected_artifact_snapshot_hits": 0,
            "full_pipeline_validation_issue_count": 0,
            "full_pipeline_expected_authoritative_change_fact_count": 0,
            "full_pipeline_expected_formal_api_result_count": 0,
            "full_pipeline_expected_authoritative_member_change_kind_counts": {},
            "full_pipeline_expected_formal_reachability_status_counts": {},
            "full_pipeline_expected_formal_impact_conclusion_counts": {},
            "changed_full_pipeline_expected_class_count": 2,
            "changed_full_pipeline_expected_parser_invocations": 1,
            "changed_full_pipeline_expected_artifact_snapshot_hits": 0,
            "changed_full_pipeline_validation_issue_count": 0,
            "changed_full_pipeline_expected_authoritative_change_fact_count": 0,
            "changed_full_pipeline_expected_formal_api_result_count": 0,
            "changed_full_pipeline_expected_authoritative_member_change_kind_counts": {},
            "changed_full_pipeline_expected_formal_reachability_status_counts": {},
            "changed_full_pipeline_expected_formal_impact_conclusion_counts": {},
        }
        return result, {
            "measurement_protocol": deepcopy(protocol),
            "thresholds": thresholds,
            "accuracy_invariants": invariants,
        }

    @staticmethod
    def recorded_gate_fixture():
        return gate.json.loads((
            ROOT_DIR / "tests" / "fixtures" / "binary_first"
            / "performance_gate.json"
        ).read_text(encoding="utf-8"))

    def test_type_sensitive_comparison_metrics_and_command_fallbacks(self):
        self.assertFalse(gate._type_sensitive_equal(False, 0))
        self.assertFalse(gate._type_sensitive_equal({"a": 1}, {"b": 1}))
        self.assertFalse(gate._type_sensitive_equal({"a": 1}, {"a": 2}))
        self.assertTrue(gate._type_sensitive_equal({"a": [1, True]}, {"a": [1, True]}))
        self.assertFalse(gate._type_sensitive_equal([1], [1, 2]))
        self.assertFalse(gate._type_sensitive_equal([1, 2], [1, 3]))
        self.assertTrue(gate._type_sensitive_equal([1, 2], [1, 2]))

        with patch.object(gate, "_resource", None), patch.object(
            gate, "windows_current_process_usage", side_effect=OSError("unavailable"),
        ), self.assertRaises(gate.PerformanceGateError):
            gate._rss_bytes()
        with patch.object(gate, "_resource", None), patch.object(
            gate, "windows_current_process_usage", return_value=None,
        ), self.assertRaises(gate.PerformanceGateError):
            gate._rss_bytes()

        resource = Mock(RUSAGE_SELF=1, RUSAGE_CHILDREN=2)
        for own, child, expected in ((5, 9, 9), (9, 5, 9)):
            resource.getrusage.side_effect = (
                SimpleNamespace(ru_maxrss=own, ru_utime=1, ru_stime=2),
                SimpleNamespace(ru_maxrss=child, ru_utime=3, ru_stime=4),
            )
            with self.subTest(rss=(own, child)), patch.object(
                gate, "_resource", resource,
            ), patch.object(gate.sys, "platform", "darwin"):
                self.assertEqual(gate._rss_bytes(), expected)

        with patch.object(gate, "_resource", None), patch.object(
            gate, "windows_current_process_usage", side_effect=OSError("unavailable"),
        ), patch.object(gate.time, "process_time", return_value=7.5):
            self.assertEqual(gate._cpu_seconds(), 7.5)
        with patch.object(gate, "_resource", None), patch.object(
            gate, "windows_current_process_usage", return_value=None,
        ), patch.object(gate.time, "process_time", return_value=8.5):
            self.assertEqual(gate._cpu_seconds(), 8.5)

        resource.getrusage.side_effect = (
            SimpleNamespace(ru_utime=1.0, ru_stime=2.0),
            SimpleNamespace(ru_utime=3.0, ru_stime=4.0),
        )
        with patch.object(gate, "_resource", resource):
            self.assertEqual(gate._cpu_seconds(), 10.0)

        with patch.object(gate.time, "perf_counter", return_value=10.0), patch.object(
            gate, "_cpu_seconds", return_value=4.0,
        ):
            self.assertEqual(
                gate._timing_metrics(started=10.0, cpu_started=4.0)[
                    "average_cpu_cores"
                ],
                0.0,
            )
        with patch.object(gate.time, "perf_counter", return_value=12.0), patch.object(
            gate, "_cpu_seconds", return_value=5.0,
        ):
            self.assertEqual(
                gate._timing_metrics(started=10.0, cpu_started=1.0),
                {
                    "end_to_end_seconds": 2.0,
                    "cpu_seconds": 4.0,
                    "average_cpu_cores": 2.0,
                },
            )

        completed_cases = (
            (SimpleNamespace(stdout="version 1\nextra", stderr="", returncode=0), "version 1"),
            (SimpleNamespace(stdout="", stderr="error version\n", returncode=1), "error version"),
            (SimpleNamespace(stdout="", stderr="", returncode=7), "exit=7"),
        )
        for completed, expected in completed_cases:
            with patch.object(
                gate, "run_managed_subprocess", return_value=completed,
            ):
                self.assertEqual(gate._command_version(["tool"]), expected)

    def test_jdk_template_and_physical_leaf_boundary_matrix(self):
        with patch.object(
            gate, "run_managed_subprocess",
            return_value=SimpleNamespace(stderr="noise\njava.home = /tmp/jdk\n"),
        ), patch.object(Path, "resolve", return_value=Path("/physical/jdk")):
            self.assertEqual(gate._jdk_home(), Path("/physical/jdk"))
        with patch.object(
            gate, "run_managed_subprocess",
            return_value=SimpleNamespace(stderr="java.home without assignment\n"),
        ), self.assertRaises(gate.PerformanceGateError):
            gate._jdk_home()

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for value, expected in (("17.0.12", 17), ("1.8.0_402", 8)):
                (home / "release").write_text(
                    f'JAVA_VERSION="{value}"\n', encoding="utf-8",
                )
                self.assertEqual(gate._java_major(home), expected)
            (home / "release").write_text("OTHER=value\n", encoding="utf-8")
            with self.assertRaises(gate.PerformanceGateError):
                gate._java_major(home)

        with self.assertRaises(gate.PerformanceGateError):
            gate._compile_template(Path("."), return_value=99)
        with patch.dict(gate._FIXED_TEMPLATE_SHA256, {1: "0" * 64}):
            with self.assertRaisesRegex(gate.PerformanceGateError, "digest mismatch"):
                gate._compile_template(Path("."))
        content = b"valid-class-without-owner"
        with patch.object(
            gate.base64, "b64decode", return_value=content,
        ), patch.dict(
            gate._FIXED_TEMPLATE_SHA256,
            {1: gate.hashlib.sha256(content).hexdigest()},
        ):
            with self.assertRaisesRegex(gate.PerformanceGateError, "owner constant"):
                gate._compile_template(Path("."))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "directory"
            self.assertIsNone(gate._physical_directory_identity(
                root, field="root", create=False,
            ))
            identity = gate._physical_directory_identity(
                root, field="root", create=True,
            )
            self.assertEqual(len(identity), 3)
            regular = Path(temporary) / "regular"
            regular.write_bytes(b"file")
            with self.assertRaises(gate.PerformanceGateError):
                gate._physical_directory_identity(
                    regular, field="regular", create=False,
                )

        link_stat = self.stat_result(mode=stat.S_IFLNK | 0o777)
        real_lstat = os.lstat
        with patch.object(
            gate.os,
            "lstat",
            side_effect=lambda path: (
                link_stat if Path(path) == Path("/link") else real_lstat(path)
            ),
        ):
            with self.assertRaises(gate.PerformanceGateError):
                gate._physical_directory_identity(
                    Path("/link"), field="link", create=False,
                )

        regular = self.stat_result()
        variants = (
            (regular, regular, True),
            (self.stat_result(mode=stat.S_IFDIR | 0o700), regular, False),
            (regular, self.stat_result(mode=stat.S_IFDIR | 0o700), False),
            (self.stat_result(links=2), regular, False),
            (regular, self.stat_result(links=2), False),
            (self.stat_result(device=2), regular, False),
            (self.stat_result(inode=3), regular, False),
            (self.stat_result(size=4), regular, False),
        )
        for descriptor, path, expected in variants:
            self.assertIs(
                gate._same_completed_private_file(descriptor, path), expected,
            )

        with tempfile.TemporaryDirectory() as temporary:
            leaf = Path(temporary) / "leaf"
            gate._remove_existing_regular_or_link_leaf(leaf, field="leaf")
            leaf.write_bytes(b"owned")
            gate._remove_existing_regular_or_link_leaf(leaf, field="leaf")
            self.assertFalse(leaf.exists())
            leaf.mkdir()
            with self.assertRaises(gate.PerformanceGateError):
                gate._remove_existing_regular_or_link_leaf(leaf, field="leaf")

    def test_error_bounding_probe_failure_and_percentile_matrix(self):
        class BrokenTextError(Exception):
            def __str__(self):
                raise RuntimeError("cannot render")

        class BrokenKey:
            def __str__(self):
                raise RuntimeError("cannot render key")

        class BrokenRepr:
            def __repr__(self):
                raise RuntimeError("cannot repr")

        self.assertIn("unprintable", gate._safe_error_text(BrokenTextError()))
        self.assertTrue(gate._safe_error_text(ValueError("x" * 20), limit=5).endswith(
            "...[truncated]"
        ))
        self.assertIsNone(gate._bounded_json_value(None))
        self.assertIs(gate._bounded_json_value(True), True)
        self.assertEqual(gate._bounded_json_value(3), 3)
        self.assertEqual(gate._bounded_json_value(1.5), 1.5)
        self.assertEqual(gate._bounded_json_value(math.inf), "inf")
        self.assertEqual(gate._bounded_json_value("x" * 9000)[-14:], "...[truncated]")
        self.assertEqual(gate._bounded_json_value({"a": 1}, depth=4), "<dict>")
        mapping = {f"k-{index}": index for index in range(65)}
        mapping[BrokenKey()] = "ignored-after-limit"
        bounded = gate._bounded_json_value(mapping)
        self.assertTrue(bounded["__truncated__"])
        bounded_key = gate._bounded_json_value({BrokenKey(): 1})
        self.assertTrue(next(iter(bounded_key)).startswith("<unprintable"))
        sequence = gate._bounded_json_value(list(range(65)))
        self.assertEqual(sequence[-1], "...[truncated]")
        self.assertEqual(gate._bounded_json_value((1, 2)), [1, 2])
        self.assertIn("unprintable", gate._bounded_json_value(BrokenRepr()))
        self.assertEqual(gate._bounded_json_value(object())[:1], "<")

        structured = gate.PerformanceGateError(
            "failed",
            failure={"reason_code": "STRUCTURED_REASON", "detail": "private"},
        )
        self.assertEqual(gate._probe_failure(structured)["reason_code"], "STRUCTURED_REASON")
        reasoned = RuntimeError("failed")
        reasoned.reason_code = "ATTRIBUTE_REASON"
        self.assertEqual(gate._probe_failure(reasoned)["reason_code"], "ATTRIBUTE_REASON")
        self.assertEqual(
            gate._probe_failure(RuntimeError("failed"))["reason_code"],
            "BINARY_PERFORMANCE_FULL_PIPELINE_PROBE_FAILED",
        )

        with self.assertRaises(gate.PerformanceGateError):
            gate._percentile([], 0.5)
        for invalid in (0.0, 1.1):
            with self.assertRaises(gate.PerformanceGateError):
                gate._percentile([1.0], invalid)
        self.assertEqual(gate._percentile([3.0, 1.0, 2.0], 0.5), 2.0)
        self.assertEqual(gate._percentile([3.0, 1.0, 2.0], 1.0), 3.0)

    def test_changed_derivation_reference_runtime_and_binding_matrix(self):
        valid = "a" * 64
        invalid_inputs = (
            {"base_artifact_identity": "short", "current_artifact_identity": valid,
             "classes_per_jar": 1},
            {"base_artifact_identity": valid, "current_artifact_identity": "short",
             "classes_per_jar": 1},
            {"base_artifact_identity": valid, "current_artifact_identity": valid,
             "classes_per_jar": True},
            {"base_artifact_identity": valid, "current_artifact_identity": valid,
             "classes_per_jar": 0},
        )
        for values in invalid_inputs:
            with self.assertRaises(gate.PerformanceGateError):
                gate._changed_artifact_derivation_identity(**values)
        self.assertRegex(
            gate._changed_artifact_derivation_identity(
                base_artifact_identity=valid,
                current_artifact_identity="b" * 64,
                classes_per_jar=1,
            ),
            r"^[0-9a-f]{64}$",
        )

        implementation = {"jdk_preflight_identity": "c" * 64}
        for resource_value, platform_value, expected_cpu, expected_rss in (
            (object(), "linux", "resource.getrusage(self+completed_children)",
             "resource.getrusage(self+completed_children)"),
            (None, "win32", "win32.GetProcessTimes(self_only)",
             "win32.GetProcessMemoryInfo(self_peak_working_set)"),
            (None, "linux", "time.process_time(self_only_fallback)", "unavailable"),
        ):
            with patch.object(
                gate.platform, "platform", return_value="platform",
            ), patch.object(
                gate.platform, "machine", return_value="machine",
            ), patch.object(
                gate.platform, "processor", return_value="processor",
            ), patch.object(
                gate.platform, "python_version", return_value="3.14",
            ), patch.object(
                gate.platform, "python_implementation", return_value="CPython",
            ), patch.object(
                gate, "_command_version", return_value="version",
            ), patch.object(
                gate, "javap_command", return_value=["javap", "-version"],
            ), patch.object(
                gate, "_sha256", return_value="d" * 64,
            ), patch.object(
                gate, "_resource", resource_value,
            ), patch.object(gate.sys, "platform", platform_value):
                protocol = gate._reference_runtime_protocol(Path("asm.jar"), implementation)
            self.assertEqual(protocol["cpu_time_source"], expected_cpu)
            self.assertEqual(protocol["peak_rss_source"], expected_rss)

        with self.assertRaises(gate.PerformanceGateError):
            gate._require_provisional_probe_binding(
                {}, expected_evidence_sha256=valid, field="probe",
            )
        gate._require_provisional_probe_binding(
            {"pipeline_performance_authority_binding": {"evidence_sha256": valid}},
            expected_evidence_sha256=valid,
            field="probe",
        )

        with patch.object(gate, "_generation_source_identity", return_value="1" * 64), patch.object(
            gate, "_validator_source_identity", return_value="2" * 64,
        ), patch.object(gate, "_harness_source_identity", return_value="3" * 64), patch(
            "binary_validation_contract.oracle_support_manifest_identity",
            return_value="4" * 64,
        ):
            source_only = gate._performance_implementation_protocol(
                include_runtime=False,
            )
            self.assertIn("source_implementation_identity", source_only)
            with self.assertRaises(gate.PerformanceGateError):
                gate._performance_implementation_protocol(include_runtime=True)

    def test_raw_contract_recovery_and_remaining_helper_sides(self):
        resource = Mock(RUSAGE_SELF=1, RUSAGE_CHILDREN=2)
        resource.getrusage.side_effect = (
            SimpleNamespace(ru_maxrss=5),
            SimpleNamespace(ru_maxrss=9),
        )
        with patch.object(gate, "_resource", resource), patch.object(
            gate.sys, "platform", "linux",
        ):
            self.assertEqual(gate._rss_bytes(), 9 * 1024)

        non_mapping_failure = RuntimeError("failed")
        non_mapping_failure.failure = ["not", "a", "mapping"]
        self.assertEqual(
            gate._probe_failure(non_mapping_failure)["reason_code"],
            "BINARY_PERFORMANCE_FULL_PIPELINE_PROBE_FAILED",
        )

        self.assertEqual(
            gate._raw_exact_mapping({"a": 1}, {"a"}, field="value"),
            {"a": 1},
        )
        for value, fields in (([], {"a"}), ({"b": 1}, {"a"})):
            with self.subTest(raw_mapping=value), self.assertRaises(
                gate.PerformanceGateError,
            ):
                gate._raw_exact_mapping(value, fields, field="value")
        self.assertFalse(gate._raw_number_matches(-1, 1))
        self.assertFalse(gate._raw_number_matches(1, -1))
        self.assertFalse(gate._raw_number_matches(1, 2))
        self.assertTrue(gate._raw_number_matches(1, 1.0))

        self.assertEqual(
            gate._json_object_from_exact_bytes(b'{"a":1}', field="payload"),
            {"a": 1},
        )
        for content in (
            "not-bytes",
            b"\xff",
            b'{"a":1,"a":2}',
            b"[]",
        ):
            with self.subTest(json_content=content), self.assertRaises(
                gate.PerformanceGateError,
            ):
                gate._json_object_from_exact_bytes(content, field="payload")

        self.assertEqual(gate._performance_recovery_bytes({"a": 1}), b'{"a":1}\n')
        with patch.object(gate, "_PERFORMANCE_RECOVERY_MAX_BYTES", 1), self.assertRaises(
            gate.PerformanceGateError,
        ):
            gate._performance_recovery_bytes({"a": 1})

    def test_probe_worker_artifact_schema_mutation_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact_path = (Path(temporary) / "artifact.jar").resolve()
            artifact_path.write_bytes(b"artifact")
            valid = {
                "path": str(artifact_path),
                "sha256": gate.hashlib.sha256(b"artifact").hexdigest(),
                "byte_length": len(b"artifact"),
                "jar_index": 0,
                "first_class_index": 0,
                "class_count": 2,
            }
            key = (valid["path"], valid["byte_length"], valid["sha256"])
            with patch.object(gate, "_verify_probe_worker_artifact_file") as verify:
                self.assertEqual(
                    gate._validate_probe_worker_artifacts(
                        [valid], field="artifacts", classes_per_jar=2,
                        verified_files=set(),
                    ),
                    [valid],
                )
                verify.assert_called_once()
                verify.reset_mock()
                gate._validate_probe_worker_artifacts(
                    [valid], field="artifacts", classes_per_jar=2,
                    verified_files={key},
                )
                verify.assert_not_called()

            cases = []
            cases.append(("non-array", {}, None))
            cases.append(("non-object", [1], None))
            wrong_fields = dict(valid)
            wrong_fields["extra"] = True
            cases.append(("wrong-fields", [wrong_fields], None))
            for raw_path in (None, ""):
                item = dict(valid)
                item["path"] = raw_path
                cases.append((f"path-{raw_path!r}", [item], None))
            relative = dict(valid)
            relative["path"] = "artifact.jar"
            cases.append(("relative-path", [relative], None))
            noncanonical = dict(valid)
            noncanonical["path"] = (
                str(artifact_path.parent)
                + os.sep + ".." + os.sep + artifact_path.parent.name
                + os.sep + artifact_path.name
            )
            cases.append(("noncanonical-path", [noncanonical], None))
            invalid_sha = dict(valid)
            invalid_sha["sha256"] = "A" * 64
            cases.append(("invalid-sha", [invalid_sha], None))
            for name in ("byte_length", "jar_index", "first_class_index", "class_count"):
                for invalid in (True, -1):
                    item = dict(valid)
                    item[name] = invalid
                    cases.append((f"{name}-{invalid!r}", [item], None))
            zero_length = dict(valid)
            zero_length["byte_length"] = 0
            cases.append(("zero-length", [zero_length], None))
            wrong_index = dict(valid)
            wrong_index["jar_index"] = 1
            cases.append(("wrong-index", [wrong_index], None))
            wrong_first = dict(valid)
            wrong_first["first_class_index"] = 1
            cases.append(("wrong-first-class", [wrong_first], None))
            wrong_count = dict(valid)
            wrong_count["class_count"] = 1
            cases.append(("wrong-class-count", [wrong_count], None))

            for label, value, _unused in cases:
                with self.subTest(label=label), patch.object(
                    gate, "_verify_probe_worker_artifact_file",
                ), self.assertRaises(gate.PerformanceGateError):
                    gate._validate_probe_worker_artifacts(
                        value, field="artifacts", classes_per_jar=2,
                        verified_files=set(),
                    )

    def test_probe_worker_input_schema_mutation_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            asm_path = root / "asm.jar"
            asm_path.write_bytes(b"asm")
            artifact = {
                "path": str(root / "artifact.jar"),
                "sha256": "a" * 64,
                "byte_length": 1,
                "jar_index": 0,
                "first_class_index": 0,
                "class_count": 2,
            }
            valid = {
                "schema": gate.PROBE_WORKER_SCHEMA,
                "artifacts": [artifact],
                "current_artifacts": None,
                "asm_jar": str(asm_path),
                "classes_per_jar": 2,
                "expected_implementation": self.implementation(),
                "provisional_gate_path": "",
            }
            with patch.object(
                gate, "_validate_probe_worker_artifacts", return_value=[artifact],
            ):
                self.assertEqual(
                    gate._validate_probe_worker_input(valid)["artifacts"],
                    [artifact],
                )

            invalid_cases = [("non-object", [])]
            extra = deepcopy(valid)
            extra["extra"] = True
            invalid_cases.append(("wrong-fields", extra))
            wrong_schema = deepcopy(valid)
            wrong_schema["schema"] = "wrong"
            invalid_cases.append(("wrong-schema", wrong_schema))
            for value in (True, 0):
                item = deepcopy(valid)
                item["classes_per_jar"] = value
                invalid_cases.append((f"classes-{value!r}", item))
            for value in (None, ""):
                item = deepcopy(valid)
                item["asm_jar"] = value
                invalid_cases.append((f"asm-{value!r}", item))
            relative_asm = deepcopy(valid)
            relative_asm["asm_jar"] = "asm.jar"
            invalid_cases.append(("asm-relative", relative_asm))
            noncanonical_asm = deepcopy(valid)
            noncanonical_asm["asm_jar"] = (
                str(root) + os.sep + "child" + os.sep + ".." + os.sep + "asm.jar"
            )
            invalid_cases.append(("asm-noncanonical", noncanonical_asm))
            non_mapping_implementation = deepcopy(valid)
            non_mapping_implementation["expected_implementation"] = []
            invalid_cases.append(("implementation-non-object", non_mapping_implementation))
            wrong_implementation_fields = deepcopy(valid)
            del wrong_implementation_fields["expected_implementation"][
                "generation_source_identity"
            ]
            invalid_cases.append(("implementation-fields", wrong_implementation_fields))
            invalid_implementation_sha = deepcopy(valid)
            invalid_implementation_sha["expected_implementation"][
                "generation_source_identity"
            ] = "bad"
            invalid_cases.append(("implementation-sha", invalid_implementation_sha))
            source_mismatch = deepcopy(valid)
            source_mismatch["expected_implementation"][
                "source_implementation_identity"
            ] = "8" * 64
            invalid_cases.append(("source-aggregate", source_mismatch))
            runtime_mismatch = deepcopy(valid)
            runtime_mismatch["expected_implementation"][
                "runtime_implementation_identity"
            ] = "9" * 64
            invalid_cases.append(("runtime-aggregate", runtime_mismatch))
            bad_provisional_type = deepcopy(valid)
            bad_provisional_type["provisional_gate_path"] = None
            invalid_cases.append(("provisional-type", bad_provisional_type))
            relative_provisional = deepcopy(valid)
            relative_provisional["provisional_gate_path"] = "gate.json"
            invalid_cases.append(("provisional-relative", relative_provisional))
            noncanonical_provisional = deepcopy(valid)
            noncanonical_provisional["provisional_gate_path"] = (
                str(root) + os.sep + "child" + os.sep + ".." + os.sep + "gate.json"
            )
            invalid_cases.append(("provisional-noncanonical", noncanonical_provisional))

            for label, value in invalid_cases:
                with self.subTest(label=label), patch.object(
                    gate, "_validate_probe_worker_artifacts", return_value=[artifact],
                ), self.assertRaises(gate.PerformanceGateError):
                    gate._validate_probe_worker_input(value)

            with patch.object(
                gate, "_validate_probe_worker_artifacts", return_value=[],
            ), self.assertRaises(gate.PerformanceGateError):
                gate._validate_probe_worker_input(valid)
            with patch.object(
                gate, "_validate_probe_worker_artifacts",
                side_effect=([artifact], []),
            ), self.assertRaises(gate.PerformanceGateError):
                mismatch = deepcopy(valid)
                mismatch["current_artifacts"] = [artifact]
                gate._validate_probe_worker_input(mismatch)

            canonical_provisional = deepcopy(valid)
            canonical_provisional["provisional_gate_path"] = str(root / "gate.json")
            with patch.object(
                gate, "_validate_probe_worker_artifacts", return_value=[artifact],
            ):
                self.assertEqual(
                    gate._validate_probe_worker_input(canonical_provisional)[
                        "provisional_gate_path"
                    ],
                    str(root / "gate.json"),
                )
            matching_current = deepcopy(valid)
            matching_current["current_artifacts"] = [artifact]
            with patch.object(
                gate, "_validate_probe_worker_artifacts", return_value=[artifact],
            ):
                self.assertEqual(
                    gate._validate_probe_worker_input(matching_current)[
                        "current_artifacts"
                    ],
                    [artifact],
                )

    def test_probe_worker_result_semantic_rejection_matrix(self):
        artifact = {"sha256": "a" * 64}
        valid = self.valid_probe_result()
        gate._validate_probe_worker_result_contract(
            valid,
            artifacts=[artifact],
            current_artifacts=None,
            classes_per_jar=2,
            expected_mode=gate._CANDIDATE_PROBE_AUTHORITY_MODE,
        )
        mutations = []
        pipeline_peak = deepcopy(valid)
        pipeline_peak["pipeline_reported_peak_rss_bytes"] = 11
        mutations.append(("pipeline-peak", pipeline_peak))
        parser_count = deepcopy(valid)
        parser_count["parser_invocations"] = 2
        mutations.append(("parser-count", parser_count))
        snapshot_count = deepcopy(valid)
        snapshot_count.update({
            "artifact_snapshot_hits": 1,
            "artifact_snapshot_disk_hits": 1,
        })
        mutations.append(("snapshot-count", snapshot_count))
        change_count = deepcopy(valid)
        change_count.update({
            "authoritative_change_fact_count": 1,
            "authoritative_member_change_kind_counts": {"implementation_changed": 1},
        })
        mutations.append(("change-count", change_count))
        formal_count = deepcopy(valid)
        formal_count.update({
            "formal_api_result_count": 1,
            "formal_reachability_status_counts": {"not_found_in_static_analysis": 1},
            "formal_impact_conclusion_counts": {"inconclusive": 1},
        })
        mutations.append(("formal-count", formal_count))
        for label, value in mutations:
            with self.subTest(label=label), self.assertRaisesRegex(
                gate.PerformanceGateError, "probe worker result is invalid",
            ):
                gate._validate_probe_worker_result_contract(
                    value,
                    artifacts=[artifact],
                    current_artifacts=None,
                    classes_per_jar=2,
                    expected_mode=gate._CANDIDATE_PROBE_AUTHORITY_MODE,
                )

    def test_probe_artifact_stability_and_integrity_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.jar"
            content = b"abc"
            artifact.write_bytes(content)
            digest = gate.hashlib.sha256(content).hexdigest()

            gate._verify_probe_worker_artifact_file(
                artifact,
                expected_size=len(content),
                expected_sha256=digest,
                field="artifacts[0]",
            )

            invalid_simple = (
                ("declared-size", len(content) - 1, digest, artifact),
                ("declared-digest", len(content), "0" * 64, artifact),
                ("missing", len(content), digest, artifact.parent / "missing.jar"),
            )
            for label, size, expected_digest, path in invalid_simple:
                with self.subTest(label=label), self.assertRaises(
                    gate.PerformanceGateError,
                ):
                    gate._verify_probe_worker_artifact_file(
                        path,
                        expected_size=size,
                        expected_sha256=expected_digest,
                        field="artifacts[0]",
                    )
            directory = artifact.parent / "directory.jar"
            directory.mkdir()
            with self.assertRaises(gate.PerformanceGateError):
                gate._verify_probe_worker_artifact_file(
                    directory,
                    expected_size=0,
                    expected_sha256=gate.hashlib.sha256(b"").hexdigest(),
                    field="artifacts[0]",
                )

            with patch.object(
                gate.stat, "S_ISREG", side_effect=(True, False),
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "changed before verification",
            ):
                gate._verify_probe_worker_artifact_file(
                    artifact,
                    expected_size=len(content),
                    expected_sha256=digest,
                    field="artifacts[0]",
                )

            with patch.object(
                gate, "_probe_artifact_stat_identity",
                side_effect=((1,), (2,)),
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "changed before verification",
            ):
                gate._verify_probe_worker_artifact_file(
                    artifact,
                    expected_size=len(content),
                    expected_sha256=digest,
                    field="artifacts[0]",
                )

            with patch.object(
                gate, "_probe_artifact_stat_identity", return_value=(1,),
            ), patch.object(
                gate.os, "read", return_value=content + b"x",
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "byte length changed",
            ):
                gate._verify_probe_worker_artifact_file(
                    artifact,
                    expected_size=len(content),
                    expected_sha256=digest,
                    field="artifacts[0]",
                )

            with patch.object(
                gate.os, "read", return_value=b"",
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "changed during verification",
            ):
                gate._verify_probe_worker_artifact_file(
                    artifact,
                    expected_size=len(content),
                    expected_sha256=digest,
                    field="artifacts[0]",
                )

            for label, identities in (
                ("descriptor-changed", ((1,), (1,), (1,), (2,))),
                (
                    "path-changed",
                    ((1,), (1,), (1,), (1,), (1,), (2,)),
                ),
            ):
                with self.subTest(label=label), patch.object(
                    gate, "_probe_artifact_stat_identity", side_effect=identities,
                ), self.assertRaisesRegex(
                    gate.PerformanceGateError, "changed during verification",
                ):
                    gate._verify_probe_worker_artifact_file(
                        artifact,
                        expected_size=len(content),
                        expected_sha256=digest,
                        field="artifacts[0]",
                    )

    def test_raw_analysis_run_contract_mutation_matrix(self):
        valid = self.valid_analysis_run()
        self.assertEqual(
            gate._validate_raw_analysis_run(valid, field="run"), valid,
        )

        mutations = []
        for name, value in (
            ("end_to_end_seconds", 0),
            ("cpu_seconds", -1),
            ("average_cpu_cores", math.nan),
            ("bytes_per_class", 0),
            ("bytes_per_edge", False),
            ("parser_invocations", True),
            ("peak_rss_bytes", -1),
        ):
            item = deepcopy(valid)
            item[name] = value
            mutations.append((f"scalar-{name}", item))
        invalid_count = deepcopy(valid)
        invalid_count["counts"]["members"] = -1
        mutations.append(("count", invalid_count))
        invalid_inventory = deepcopy(valid)
        invalid_inventory["inventory"]["entry_count"] = True
        mutations.append(("inventory", invalid_inventory))
        invalid_stage = deepcopy(valid)
        invalid_stage["stage_seconds"]["overlay"] = math.inf
        mutations.append(("stage-number", invalid_stage))
        excessive_stages = deepcopy(valid)
        excessive_stages["stage_seconds"] = {
            name: 2.0 for name in gate._RAW_STAGE_FIELDS
        }
        mutations.append(("stage-total", excessive_stages))
        wrong_overlay = deepcopy(valid)
        wrong_overlay["overlay_status"] = "provided"
        mutations.append(("overlay-status", wrong_overlay))
        wrong_average = deepcopy(valid)
        wrong_average["average_cpu_cores"] = 0.6
        mutations.append(("average", wrong_average))
        zero_classes = deepcopy(valid)
        zero_classes["counts"]["classes"] = 0
        mutations.append(("zero-classes", zero_classes))
        zero_edges = deepcopy(valid)
        zero_edges["counts"]["edges"] = 0
        mutations.append(("zero-edges", zero_edges))
        wrong_class_bytes = deepcopy(valid)
        wrong_class_bytes["bytes_per_class"] = 21.0
        mutations.append(("bytes-per-class", wrong_class_bytes))
        wrong_edge_bytes = deepcopy(valid)
        wrong_edge_bytes["bytes_per_edge"] = 6.0
        mutations.append(("bytes-per-edge", wrong_edge_bytes))

        for label, value in mutations:
            with self.subTest(label=label), self.assertRaises(
                gate.PerformanceGateError,
            ):
                gate._validate_raw_analysis_run(value, field="run")

    def test_raw_probe_contract_mutation_matrix(self):
        implementation = self.implementation()
        source = implementation["source_implementation_identity"]
        mode = gate._CANDIDATE_PROBE_AUTHORITY_MODE
        valid = self.valid_raw_probe(mode=mode, source_identity=source)
        self.assertEqual(
            set(valid), gate._RECORDED_PROBE_FIELDS - {"captured_at"},
        )
        self.assertEqual(
            gate._validate_raw_probe(
                valid,
                field="probe",
                expected_mode=mode,
                expected_source_identity=source,
            ),
            valid,
        )
        valid_nonempty_histogram = deepcopy(valid)
        valid_nonempty_histogram[
            "formal_reachability_status_counts"
        ] = {"valid": 0}
        gate._validate_raw_probe(
            valid_nonempty_histogram,
            field="probe",
            expected_mode=mode,
            expected_source_identity=source,
        )

        mutations = []
        for name, value in (("status", ""), ("comparison", 1)):
            item = deepcopy(valid)
            item[name] = value
            mutations.append((f"string-{name}", item))
        for name in ("performance_authority_mode", "activation_authority_mode"):
            item = deepcopy(valid)
            item[name] = "wrong-mode"
            mutations.append((f"mode-{name}", item))
        for name, value in (
            ("process_id", 0),
            ("jar_count", True),
            ("peak_rss_bytes", -1),
        ):
            item = deepcopy(valid)
            item[name] = value
            mutations.append((f"integer-{name}", item))
        for name, value in (
            ("end_to_end_seconds", 0),
            ("pipeline_reported_seconds", -1),
            ("cpu_seconds", math.inf),
            ("average_cpu_cores", False),
        ):
            item = deepcopy(valid)
            item[name] = value
            mutations.append((f"number-{name}", item))
        wrong_average = deepcopy(valid)
        wrong_average["average_cpu_cores"] = 0.75
        mutations.append(("average", wrong_average))
        invalid_boolean = deepcopy(valid)
        invalid_boolean["publication_deferred"] = 0
        mutations.append(("boolean", invalid_boolean))
        invalid_phase = deepcopy(valid)
        invalid_phase["phase_seconds"][gate.FULL_PIPELINE_PHASES[0]] = math.nan
        mutations.append(("phase-seconds", invalid_phase))
        invalid_peak = deepcopy(valid)
        invalid_peak["phase_peak_rss_bytes"][gate.FULL_PIPELINE_PHASES[0]] = True
        mutations.append(("phase-peaks", invalid_peak))
        histogram_shape = deepcopy(valid)
        histogram_shape["formal_reachability_status_counts"] = []
        mutations.append(("histogram-shape", histogram_shape))
        histogram_key = deepcopy(valid)
        histogram_key["formal_reachability_status_counts"] = {"": 0}
        mutations.append(("histogram-key", histogram_key))
        histogram_count = deepcopy(valid)
        histogram_count["formal_reachability_status_counts"] = {"valid": True}
        mutations.append(("histogram-count", histogram_count))
        invalid_binding = deepcopy(valid)
        invalid_binding["pipeline_performance_authority_binding"][
            "binding_identity"
        ] = "0" * 64
        mutations.append(("authority-binding", invalid_binding))

        for label, value in mutations:
            with self.subTest(label=label), self.assertRaises(
                gate.PerformanceGateError,
            ):
                gate._validate_raw_probe(
                    value,
                    field="probe",
                    expected_mode=mode,
                    expected_source_identity=source,
                )

    def test_raw_release_result_contract_mutation_matrix(self):
        mode = gate._CANDIDATE_PROBE_AUTHORITY_MODE
        valid = self.valid_raw_release_result(mode=mode)
        self.assertEqual(
            gate._validate_raw_release_result(
                valid, expected_probe_mode=mode,
            ),
            valid,
        )

        mutations = []
        for name, value in (("schema", "wrong"), ("status", "passed")):
            item = deepcopy(valid)
            item[name] = value
            mutations.append((f"root-{name}", item))
        invalid_component = deepcopy(valid)
        invalid_component["measurement_protocol"]["implementation"][
            "generation_source_identity"
        ] = "bad"
        mutations.append(("implementation-component", invalid_component))
        for label, target in (
            ("implementation-source", ("implementation", "source_implementation_identity")),
            ("implementation-runtime", ("implementation", "runtime_implementation_identity")),
            ("protocol-source", (None, "source_implementation_identity")),
            ("protocol-runtime", (None, "runtime_implementation_identity")),
        ):
            item = deepcopy(valid)
            container, name = target
            if container:
                item["measurement_protocol"][container][name] = "f" * 64
            else:
                item["measurement_protocol"][name] = "f" * 64
            mutations.append((label, item))
        non_array_warm = deepcopy(valid)
        non_array_warm["measurements"]["warm_runs"] = {}
        mutations.append(("warm-shape", non_array_warm))
        for value in (None, {}, {"warm": True}, {"warm": 2}):
            item = deepcopy(valid)
            item["measurement_protocol"]["sample_runs"] = value
            mutations.append((f"warm-count-{value!r}", item))
        for name, value in (("class_count", True), ("peak_rss_bytes", -1)):
            item = deepcopy(valid)
            item["measurements"]["legacy"][name] = value
            mutations.append((f"legacy-integer-{name}", item))
        for name, value in (
            ("end_to_end_seconds", 0),
            ("cpu_seconds", -1),
            ("average_cpu_cores", math.nan),
        ):
            item = deepcopy(valid)
            item["measurements"]["legacy"][name] = value
            mutations.append((f"legacy-number-{name}", item))
        wrong_legacy = deepcopy(valid)
        wrong_legacy["measurements"]["legacy"]["implementation"] = "wrong"
        mutations.append(("legacy-implementation", wrong_legacy))
        wrong_legacy_average = deepcopy(valid)
        wrong_legacy_average["measurements"]["legacy"][
            "average_cpu_cores"
        ] = 0.75
        mutations.append(("legacy-average", wrong_legacy_average))
        binding_mismatch = deepcopy(valid)
        source = binding_mismatch["measurement_protocol"]["source_implementation_identity"]
        binding_mismatch["measurements"]["changed_full_pipeline_probe"][
            "pipeline_performance_authority_binding"
        ] = self.authority_binding(source, mode=mode, salt="c")
        mutations.append(("probe-bindings", binding_mismatch))
        for name in (
            "warm_end_to_end_p50_seconds",
            "warm_end_to_end_p95_seconds",
            "cold_relative_legacy_ratio",
            "total_measured_wall_seconds",
            "total_measured_cpu_seconds",
            "average_cpu_cores",
        ):
            item = deepcopy(valid)
            item["measurements"][name] += 1
            mutations.append((f"aggregate-{name}", item))
        for name, value in (
            ("peak_rss_bytes", True),
            ("peak_rss_bytes", 101),
            ("disk_bytes", True),
            ("disk_bytes", 201),
        ):
            item = deepcopy(valid)
            item["measurements"][name] = value
            mutations.append((f"aggregate-{name}-{value!r}", item))

        for label, value in mutations:
            with self.subTest(label=label), self.assertRaises(
                gate.PerformanceGateError,
            ):
                gate._validate_raw_release_result(
                    value, expected_probe_mode=mode,
                )

    def test_live_gate_evaluation_protocol_threshold_and_invariant_matrix(self):
        result, policy_gate = self.valid_gate_evaluation_pair()
        passed = gate.evaluate_gate(result, policy_gate)
        self.assertEqual(passed["status"], "passed", passed["issues"])

        sparse = gate.evaluate_gate(result, {})
        self.assertEqual(sparse["status"], "failed")
        self.assertTrue(sparse["issues"])

        no_cpu = deepcopy(result)
        no_cpu["measurement_protocol"]["cpu_time_source"] = ""
        self.assertEqual(
            gate.evaluate_gate(no_cpu, policy_gate)["schema"],
            "java-upgrade-analyzer.binary-performance-gate-evaluation.v1",
        )

        mismatched_gate = deepcopy(policy_gate)
        for field in (
            "machine_identity", "dataset_identity", "jar_count", "class_count",
            "source_implementation_identity", "runtime_implementation_identity",
        ):
            mismatched_gate["measurement_protocol"][field] = "wrong"
        for field in mismatched_gate["measurement_protocol"][
            "full_pipeline_probe"
        ]:
            mismatched_gate["measurement_protocol"]["full_pipeline_probe"][
                field
            ] = "wrong"
        for field in mismatched_gate["measurement_protocol"][
            "changed_full_pipeline_probe"
        ]:
            mismatched_gate["measurement_protocol"][
                "changed_full_pipeline_probe"
            ][field] = "wrong"
        for field in mismatched_gate["thresholds"]:
            if isinstance(mismatched_gate["thresholds"][field], dict):
                mismatched_gate["thresholds"][field] = {
                    name: -1 for name in mismatched_gate["thresholds"][field]
                }
            else:
                mismatched_gate["thresholds"][field] = -1
        for field in mismatched_gate["accuracy_invariants"]:
            value = mismatched_gate["accuracy_invariants"][field]
            mismatched_gate["accuracy_invariants"][field] = (
                {"wrong": 1} if isinstance(value, dict) else 999
            )
        mismatched = gate.evaluate_gate(result, mismatched_gate)
        self.assertEqual(mismatched["status"], "failed")
        reason_codes = {item["reason_code"] for item in mismatched["issues"]}
        self.assertIn("BINARY_PERFORMANCE_PROTOCOL_MISMATCH", reason_codes)
        self.assertIn("BINARY_PERFORMANCE_THRESHOLD_EXCEEDED", reason_codes)
        self.assertIn("BINARY_PERFORMANCE_FACT_CONSERVATION_FAILED", reason_codes)
        self.assertIn("BINARY_PERFORMANCE_FULL_PIPELINE_RESULT_MISMATCH", reason_codes)

        implementation_cases = []
        invalid_component = deepcopy(result)
        invalid_component["measurement_protocol"]["implementation"][
            "generation_source_identity"
        ] = "bad"
        implementation_cases.append(invalid_component)
        derived_source = deepcopy(result)
        derived_source["measurement_protocol"]["implementation"][
            "source_implementation_identity"
        ] = "f" * 64
        implementation_cases.append(derived_source)
        protocol_source = deepcopy(result)
        protocol_source["measurement_protocol"][
            "source_implementation_identity"
        ] = "f" * 64
        implementation_cases.append(protocol_source)
        derived_runtime = deepcopy(result)
        derived_runtime["measurement_protocol"]["implementation"][
            "runtime_implementation_identity"
        ] = "f" * 64
        implementation_cases.append(derived_runtime)
        protocol_runtime = deepcopy(result)
        protocol_runtime["measurement_protocol"][
            "runtime_implementation_identity"
        ] = "f" * 64
        implementation_cases.append(protocol_runtime)
        for index, value in enumerate(implementation_cases):
            with self.subTest(implementation=index):
                evaluation = gate.evaluate_gate(value, policy_gate)
                self.assertIn(
                    "BINARY_PERFORMANCE_IMPLEMENTATION_IDENTITY_INVALID",
                    {item["reason_code"] for item in evaluation["issues"]},
                )

        derivation_cases = []
        for metric, value in (
            ("warm_end_to_end_p50_seconds", None),
            ("warm_end_to_end_p95_seconds", 12.0),
        ):
            item = deepcopy(result)
            item["measurements"][metric] = value
            derivation_cases.append(item)
        for value in derivation_cases:
            evaluation = gate.evaluate_gate(value, policy_gate)
            self.assertIn(
                "BINARY_PERFORMANCE_DERIVATION_INVALID",
                {item["reason_code"] for item in evaluation["issues"]},
            )

        cpu_cases = (
            ("end_to_end_seconds", True),
            ("cpu_seconds", True),
            ("average_cpu_cores", True),
            ("end_to_end_seconds", 0),
            ("cpu_seconds", -1),
            ("average_cpu_cores", -1),
            ("average_cpu_cores", 0.75),
            ("cpu_seconds", "not-a-number"),
        )
        for field, value in cpu_cases:
            item = deepcopy(result)
            item["measurements"]["cold"][field] = value
            with self.subTest(cpu_field=field, value=value):
                evaluation = gate.evaluate_gate(item, policy_gate)
                self.assertIn(
                    "BINARY_PERFORMANCE_CPU_MEASUREMENT_INVALID",
                    {issue["reason_code"] for issue in evaluation["issues"]},
                )

        no_legacy = deepcopy(result)
        no_legacy["measurements"]["legacy"] = {}
        no_legacy["measurement_protocol"]["cpu_time_source"] = ""
        no_legacy_evaluation = gate.evaluate_gate(no_legacy, policy_gate)
        self.assertIsNone(no_legacy_evaluation["warm_relative_legacy_ratio"])

        fallback_sides = deepcopy(result)
        for probe_name in ("full_pipeline_probe", "changed_full_pipeline_probe"):
            fallback_sides["measurements"][probe_name].pop("base_class_count")
            fallback_sides["measurements"][probe_name].pop("current_class_count")
        self.assertEqual(
            gate.evaluate_gate(fallback_sides, policy_gate)["status"], "passed",
        )

    def test_live_gate_empty_optional_structures_fail_closed(self):
        result, policy_gate = self.valid_gate_evaluation_pair()
        cases = []
        for label, path in (
            ("protocol", ("measurement_protocol",)),
            ("probe-protocol", ("measurement_protocol", "full_pipeline_probe")),
            (
                "changed-probe-protocol",
                ("measurement_protocol", "changed_full_pipeline_probe"),
            ),
            ("implementation", ("measurement_protocol", "implementation")),
            ("measurements", ("measurements",)),
            ("cold", ("measurements", "cold")),
            ("warm-runs", ("measurements", "warm_runs")),
            ("full-probe", ("measurements", "full_pipeline_probe")),
            (
                "changed-full-probe",
                ("measurements", "changed_full_pipeline_probe"),
            ),
            ("legacy", ("measurements", "legacy")),
            (
                "full-phase-seconds",
                ("measurements", "full_pipeline_probe", "phase_seconds"),
            ),
            (
                "changed-phase-seconds",
                (
                    "measurements", "changed_full_pipeline_probe",
                    "phase_seconds",
                ),
            ),
            ("cold-stage-seconds", ("measurements", "cold", "stage_seconds")),
            (
                "warm-stage-seconds",
                ("measurements", "warm_runs", 0, "stage_seconds"),
            ),
            ("counts", ("measurements", "cold", "counts")),
        ):
            item = deepcopy(result)
            cursor = item
            for component in path[:-1]:
                cursor = cursor[component]
            cursor[path[-1]] = {}
            cases.append((label, item))
        zero_warm_ratio = deepcopy(result)
        zero_warm_ratio["measurements"]["warm_end_to_end_p95_seconds"] = 0
        cases.append(("zero-warm-ratio", zero_warm_ratio))

        for label, value in cases:
            with self.subTest(label=label):
                evaluation = gate.evaluate_gate(value, policy_gate)
                self.assertEqual(evaluation["status"], "failed")
                self.assertTrue(evaluation["issues"])

    def test_recorded_measurement_reduction_contract(self):
        raw = self.valid_raw_release_result()
        captured_at = "2026-08-23T00:00:00Z"
        recorded = gate._recorded_measurements_from_result(
            raw, captured_at=captured_at,
        )
        self.assertEqual(recorded["captured_at"], captured_at)
        self.assertEqual(
            recorded["full_pipeline_probe"]["captured_at"], captured_at,
        )
        self.assertEqual(recorded["class_count"], 10)
        self.assertEqual(recorded["disk_bytes"], 200)

        with self.assertRaises(gate.PerformanceGateError):
            gate._recorded_measurements_from_result(
                {"measurements": None}, captured_at=captured_at,
            )
        no_warm = deepcopy(raw)
        no_warm["measurements"]["warm_runs"] = []
        with self.assertRaisesRegex(
            gate.PerformanceGateError, "at least one warm sample",
        ):
            gate._recorded_measurements_from_result(
                no_warm, captured_at=captured_at,
            )

    def test_exact_byte_publication_transaction_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "authority.json"
            content = b'{"status":"passed"}\n'
            gate._write_exact_bytes(output, content)
            self.assertEqual(output.read_bytes(), content)
            with self.assertRaises(gate.PerformanceGateError):
                gate._write_exact_bytes(output, "not-bytes")

            created = self.stat_result(size=0)
            completion_variants = (
                self.stat_result(mode=stat.S_IFDIR | 0o700),
                self.stat_result(links=2),
                self.stat_result(device=2),
                self.stat_result(inode=3),
            )
            for index, completed in enumerate(completion_variants):
                target = root / f"completion-{index}.json"
                with self.subTest(completed=index), patch.object(
                    gate.os, "fstat", side_effect=(created, completed),
                ), self.assertRaisesRegex(
                    gate.PerformanceGateError, "changed while being written",
                ):
                    gate._write_exact_bytes(target, content)
                self.assertFalse(target.exists())

            for index, created_invalid in enumerate((
                self.stat_result(mode=stat.S_IFDIR | 0o700, size=0),
                self.stat_result(links=2, size=0),
            )):
                target = root / f"creation-{index}.json"
                with self.subTest(created=index), patch.object(
                    gate.os, "fstat", return_value=created_invalid,
                ), self.assertRaisesRegex(
                    gate.PerformanceGateError, "not a private regular file",
                ):
                    gate._write_exact_bytes(target, content)
                self.assertFalse(target.exists())

            replaced = root / "replaced.json"
            with patch.object(
                gate, "_same_completed_private_file", return_value=False,
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "replaced before publication",
            ):
                gate._write_exact_bytes(replaced, content)
            self.assertFalse(replaced.exists())

    def test_atomic_zip_publication_transaction_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "dataset.zip"
            with gate._atomic_zip_archive(output, field="dataset") as archive:
                archive.writestr("entry.txt", b"entry")
            with gate.zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.read("entry.txt"), b"entry")

            created = self.stat_result(size=0)
            for index, completed in enumerate((
                self.stat_result(mode=stat.S_IFDIR | 0o700),
                self.stat_result(links=2),
                self.stat_result(device=2),
                self.stat_result(inode=3),
            )):
                target = root / f"changed-{index}.zip"
                with self.subTest(completed=index), patch.object(
                    gate.os, "fstat", side_effect=(created, completed),
                ), self.assertRaisesRegex(
                    gate.PerformanceGateError, "changed while being written",
                ):
                    with gate._atomic_zip_archive(target, field="dataset") as archive:
                        archive.writestr("entry.txt", b"entry")
                self.assertFalse(target.exists())

            for index, created_invalid in enumerate((
                self.stat_result(mode=stat.S_IFDIR | 0o700, size=0),
                self.stat_result(links=2, size=0),
            )):
                target = root / f"invalid-{index}.zip"
                with self.subTest(created=index), patch.object(
                    gate.os, "fstat", return_value=created_invalid,
                ), self.assertRaisesRegex(
                    gate.PerformanceGateError, "not a private regular file",
                ):
                    with gate._atomic_zip_archive(target, field="dataset"):
                        pass
                self.assertFalse(target.exists())

            replaced = root / "replaced.zip"
            with patch.object(
                gate, "_same_completed_private_file", return_value=False,
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "replaced before publication",
            ):
                with gate._atomic_zip_archive(replaced, field="dataset") as archive:
                    archive.writestr("entry.txt", b"entry")
            self.assertFalse(replaced.exists())

            directory_changed = root / "directory-changed.zip"
            with patch.object(
                gate, "_physical_directory_identity",
                side_effect=((1, 2, 3), (4, 5, 6)),
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "directory changed",
            ):
                with gate._atomic_zip_archive(
                    directory_changed, field="dataset",
                ) as archive:
                    archive.writestr("entry.txt", b"entry")
            self.assertFalse(directory_changed.exists())

            with self.assertRaisesRegex(
                gate.PerformanceGateError, "archive cannot be published safely",
            ):
                with gate._atomic_zip_archive(
                    root / "body-oserror.zip", field="dataset",
                ):
                    raise OSError("injected body failure")
            injected = gate.PerformanceGateError("injected domain failure")
            with self.assertRaises(gate.PerformanceGateError) as raised:
                with gate._atomic_zip_archive(
                    root / "body-domain.zip", field="dataset",
                ):
                    raise injected
            self.assertIs(raised.exception, injected)

    def test_provisional_snapshot_stability_matrix(self):
        content = b'{"status":"passed"}\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, digest = gate._snapshot_provisional_gate(root, content)
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(digest, gate.hashlib.sha256(content).hexdigest())
            with self.assertRaises(gate.PerformanceGateError):
                gate._snapshot_provisional_gate(root, "not-bytes")

            with patch.object(
                gate, "_write_exact_bytes", side_effect=OSError("write failed"),
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "cannot be persisted",
            ):
                gate._snapshot_provisional_gate(root, content)
            injected = gate.PerformanceGateError("domain failure")
            with patch.object(
                gate, "_write_exact_bytes", side_effect=injected,
            ), self.assertRaises(gate.PerformanceGateError) as raised:
                gate._snapshot_provisional_gate(root, content)
            self.assertIs(raised.exception, injected)

            authority = root.resolve() / "provisional-authority"
            snapshot = authority / (
                f"provisional-gate-{gate.hashlib.sha256(content).hexdigest()}.json"
            )
            snapshot.write_bytes(content)
            real_lstat = os.lstat
            for label, fake_stat in (
                ("non-regular", self.stat_result(mode=stat.S_IFDIR | 0o700)),
                ("linked", self.stat_result(links=2, size=len(content))),
                ("size", self.stat_result(size=len(content) + 1)),
            ):
                def fake_lstat(path_value, *, expected=fake_stat):
                    if Path(path_value) == snapshot:
                        return expected
                    return real_lstat(path_value)
                with self.subTest(label=label), patch.object(
                    gate, "_write_exact_bytes",
                ), patch.object(
                    gate.os, "lstat", side_effect=fake_lstat,
                ), self.assertRaisesRegex(
                    gate.PerformanceGateError, "not a private regular file",
                ):
                    gate._snapshot_provisional_gate(root, content)

            with patch.object(
                gate, "_write_exact_bytes",
            ), patch.object(
                gate.os, "fstat", return_value=self.stat_result(links=2),
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "changed before verification",
            ):
                gate._snapshot_provisional_gate(root, content)

            with patch.object(
                gate, "_write_exact_bytes",
            ), patch.object(
                gate, "_probe_artifact_stat_identity",
                side_effect=((1,), (2,)),
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "changed before verification",
            ):
                gate._snapshot_provisional_gate(root, content)

            with patch.object(
                gate, "_write_exact_bytes",
            ), patch.object(
                gate, "_probe_artifact_stat_identity", return_value=(1,),
            ), patch.object(
                gate.os, "read", return_value=content + b"x",
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "byte length changed",
            ):
                gate._snapshot_provisional_gate(root, content)

            with patch.object(
                gate, "_write_exact_bytes",
            ), patch.object(
                gate.os, "fstat", side_effect=(
                    self.stat_result(links=1, size=len(content)),
                    self.stat_result(links=2, size=len(content)),
                ),
            ), patch.object(
                gate, "_probe_artifact_stat_identity", return_value=(1,),
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "does not match",
            ):
                gate._snapshot_provisional_gate(root, content)

            with patch.object(
                gate, "_write_exact_bytes",
            ), patch.object(
                gate, "_probe_artifact_stat_identity", return_value=(1,),
            ), patch.object(
                gate.os, "read", return_value=b"",
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "does not match",
            ):
                gate._snapshot_provisional_gate(root, content)

            for label, identities in (
                ("descriptor", ((1,), (1,), (1,), (2,))),
                ("path", ((1,), (1,), (1,), (1,), (1,), (2,))),
            ):
                with self.subTest(label=label), patch.object(
                    gate, "_write_exact_bytes",
                ), patch.object(
                    gate, "_probe_artifact_stat_identity", side_effect=identities,
                ), self.assertRaisesRegex(
                    gate.PerformanceGateError, "does not match",
                ):
                    gate._snapshot_provisional_gate(root, content)

            with patch.object(
                gate, "_write_exact_bytes",
            ), patch.object(
                gate, "_probe_artifact_stat_identity", return_value=(1,),
            ), patch.object(
                gate, "_physical_directory_identity",
                side_effect=((1, 2, 3), (4, 5, 6)),
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "directory changed",
            ):
                gate._snapshot_provisional_gate(root, content)

    def test_recovery_persistence_and_cli_output_path_matrix(self):
        result = {"status": "passed", "value": 1}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch(
                "binary_pipeline._write_non_authoritative_json",
                return_value=True,
            ):
                persisted = gate._persist_completed_benchmark_recovery(root, result)
            self.assertFalse(persisted["recovery_is_temporary"])
            self.assertTrue(Path(persisted["recovery_path"]).is_absolute())

            for behavior in (False, OSError("primary failed")):
                kwargs = (
                    {"return_value": behavior}
                    if behavior is False else {"side_effect": behavior}
                )
                with patch(
                    "binary_pipeline._write_non_authoritative_json", **kwargs,
                ):
                    fallback = gate._persist_completed_benchmark_recovery(root, result)
                self.assertTrue(fallback["recovery_is_temporary"])
                self.assertTrue(fallback["work_root_recovery_error"])
                Path(fallback["recovery_path"]).unlink()

            with patch(
                "binary_pipeline._write_non_authoritative_json",
                return_value=False,
            ), patch.object(
                gate, "_same_completed_private_file", return_value=False,
            ):
                failed_fallback = gate._persist_completed_benchmark_recovery(
                    root, result,
                )
            self.assertFalse(failed_fallback["recovery_is_temporary"])
            self.assertTrue(failed_fallback["temporary_recovery_error"])

            with patch(
                "binary_pipeline._write_non_authoritative_json",
                return_value=False,
            ), patch.object(
                gate.tempfile, "mkstemp", side_effect=OSError("no temp file"),
            ):
                no_path = gate._persist_completed_benchmark_recovery(root, result)
            self.assertFalse(no_path["recovery_is_temporary"])
            self.assertIn("no temp file", no_path["temporary_recovery_error"])

            opened_descriptors = []
            real_mkstemp = tempfile.mkstemp
            def tracked_mkstemp(*args, **kwargs):
                descriptor, name = real_mkstemp(*args, **kwargs)
                opened_descriptors.append(descriptor)
                return descriptor, name
            with patch(
                "binary_pipeline._write_non_authoritative_json",
                return_value=False,
            ), patch.object(
                gate.tempfile, "mkstemp", side_effect=tracked_mkstemp,
            ), patch.object(
                gate.os, "fdopen", side_effect=OSError("fdopen failed"),
            ):
                descriptor_failure = gate._persist_completed_benchmark_recovery(
                    root, result,
                )
            self.assertFalse(descriptor_failure["recovery_is_temporary"])
            self.assertIn(
                "fdopen failed", descriptor_failure["temporary_recovery_error"],
            )
            for descriptor in opened_descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

            parser = argparse.ArgumentParser(add_help=False)
            regular = root / "output.json"
            regular.write_bytes(b"old")
            self.assertEqual(
                gate._distinct_cli_output_path(
                    parser, str(regular), protected_values=(),
                ),
                regular.parent.resolve() / regular.name,
            )
            for value in ("", ".", ".."):
                with self.subTest(output=value), redirect_stderr(
                    io.StringIO()
                ), self.assertRaises(SystemExit):
                    gate._distinct_cli_output_path(
                        parser, value, protected_values=(),
                    )
            directory = root / "directory-output"
            directory.mkdir()
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                gate._distinct_cli_output_path(
                    parser, str(directory), protected_values=(),
                )
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                gate._distinct_cli_output_path(
                    parser, str(regular), protected_values=(str(regular),),
                )
            absent = root / "absent.json"
            distinct = root / "distinct.json"
            distinct.write_bytes(b"distinct")
            self.assertEqual(
                gate._distinct_cli_output_path(
                    parser,
                    str(absent),
                    protected_values=("", str(distinct)),
                ),
                absent.parent.resolve() / absent.name,
            )
            link = root / "linked-output.json"
            try:
                link.symlink_to(regular)
            except OSError:
                link = None
            if link is not None:
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    gate._distinct_cli_output_path(
                        parser, str(link), protected_values=(),
                    )

    def test_isolated_probe_response_contract_matrix(self):
        implementation = self.implementation()
        artifacts = [{"sha256": "a" * 64}]

        def invoke(
            response, *, returncode=0, provisional=False, stale=False,
            stderr="worker stderr", expected_value=None,
        ):
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
            output = root / "isolated_probe_result.json"
            if stale:
                output.write_text("stale", encoding="utf-8")

            def run_worker(*_args, **_kwargs):
                if isinstance(response, bytes):
                    output.write_bytes(response)
                elif response is not None:
                    output.write_text(
                        gate.json.dumps(response), encoding="utf-8",
                    )
                return SimpleNamespace(returncode=returncode, stderr=stderr)

            with patch.object(
                gate, "run_managed_subprocess", side_effect=run_worker,
            ):
                return gate._run_isolated_full_pipeline_probe(
                    artifacts,
                    root=root,
                    asm_jar=Path("/asm.jar"),
                    classes_per_jar=2,
                    expected_implementation=expected_value or implementation,
                    provisional_gate_path=(
                        root / "provisional.json" if provisional else None
                    ),
                )

        candidate = self.valid_raw_probe(
            mode=gate._CANDIDATE_PROBE_AUTHORITY_MODE,
            source_identity=implementation["source_implementation_identity"],
        )
        candidate["process_id"] = max(os.getpid() + 1, 2)
        success_response = {
            "schema": gate.PROBE_WORKER_SCHEMA,
            "status": "passed",
            "result": candidate,
        }
        self.assertEqual(
            invoke(success_response, stale=True)["process_id"],
            candidate["process_id"],
        )

        recapture = self.valid_raw_probe(
            mode=gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE,
            source_identity=implementation["source_implementation_identity"],
        )
        recapture["process_id"] = max(os.getpid() + 1, 2)
        self.assertEqual(
            invoke({
                "schema": gate.PROBE_WORKER_SCHEMA,
                "status": "passed",
                "result": recapture,
            }, provisional=True)["activation_authority_mode"],
            gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE,
        )

        for label, response in (
            ("missing-output", None),
            ("invalid-json", b"not-json"),
        ):
            with self.subTest(label=label), self.assertRaises(
                gate.PerformanceGateError,
            ) as raised:
                invoke(response, returncode=1)
            self.assertEqual(
                raised.exception.failure["reason_code"],
                "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
            )
        with self.assertRaises(gate.PerformanceGateError):
            invoke(None, returncode=1, stderr="")

        valid_failure = {
            "schema": gate.PROBE_WORKER_SCHEMA,
            "status": "failed",
            "failure": {
                "reason_code": "WORKER_FAILED",
                "error_type": "RuntimeError",
                "detail": "failure detail",
            },
        }
        with self.assertRaises(gate.PerformanceGateError) as raised:
            invoke(valid_failure, returncode=1)
        self.assertEqual(raised.exception.failure["reason_code"], "WORKER_FAILED")

        failure_mutations = []
        for label, mutate, code in (
            ("schema", lambda value: value.update(schema="wrong"), 1),
            ("fields", lambda value: value.update(extra=True), 1),
            ("failure-shape", lambda value: value.update(failure=[]), 1),
            (
                "failure-fields",
                lambda value: value["failure"].update(extra=True),
                1,
            ),
            (
                "failure-empty",
                lambda value: value["failure"].update(detail=""),
                1,
            ),
            (
                "failure-non-string",
                lambda value: value["failure"].update(detail=1),
                1,
            ),
            ("exit-code", lambda _value: None, 0),
        ):
            value = deepcopy(valid_failure)
            mutate(value)
            failure_mutations.append((label, value, code))
        for label, response, code in failure_mutations:
            with self.subTest(failure=label), self.assertRaises(
                gate.PerformanceGateError,
            ) as raised:
                invoke(response, returncode=code)
            self.assertEqual(
                raised.exception.failure["reason_code"],
                "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
            )
        with self.assertRaises(gate.PerformanceGateError):
            invoke(valid_failure, returncode=1, stderr="")

        success_mutations = []
        for label, mutate, code in (
            ("status", lambda value: value.update(status="unknown"), 0),
            ("schema", lambda value: value.update(schema="wrong"), 0),
            ("fields", lambda value: value.update(extra=True), 0),
            ("exit-code", lambda _value: None, 1),
        ):
            value = deepcopy(success_response)
            mutate(value)
            success_mutations.append((label, value, code))
        for label, response, code in success_mutations:
            with self.subTest(success=label), self.assertRaises(
                gate.PerformanceGateError,
            ) as raised:
                invoke(response, returncode=code)
            self.assertEqual(
                raised.exception.failure["reason_code"],
                "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
            )
        empty_stderr_success = deepcopy(success_response)
        empty_stderr_success["status"] = "unknown"
        with self.assertRaises(gate.PerformanceGateError):
            invoke(empty_stderr_success, stderr="")

        same_process = deepcopy(success_response)
        same_process["result"]["process_id"] = os.getpid()
        with self.assertRaises(gate.PerformanceGateError) as raised:
            invoke(same_process)
        self.assertEqual(
            raised.exception.failure["reason_code"],
            "BINARY_PERFORMANCE_PROBE_NOT_ISOLATED",
        )

        invalid_result = deepcopy(success_response)
        invalid_result["result"]["status"] = "wrong"
        with self.assertRaises(gate.PerformanceGateError) as raised:
            invoke(invalid_result)
        self.assertEqual(
            raised.exception.failure["reason_code"],
            "BINARY_PERFORMANCE_PROBE_OUTPUT_INVALID",
        )
        with self.assertRaises(gate.PerformanceGateError):
            invoke(invalid_result, stderr="")

        no_source = deepcopy(implementation)
        no_source["source_implementation_identity"] = ""
        with self.assertRaises(gate.PerformanceGateError):
            invoke(success_response, expected_value=no_source)

    def test_probe_worker_execution_and_failure_persistence_matrix(self):
        implementation = self.implementation()
        spec = {
            "artifacts": [{"sha256": "a" * 64}],
            "current_artifacts": None,
            "asm_jar": "/asm.jar",
            "classes_per_jar": 2,
            "expected_implementation": implementation,
            "provisional_gate_path": "",
        }

        def invoke(
            *, spec_value=None, protocol_values=None,
            pipeline_result=None, private_root=None, write_error=None,
        ):
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
            input_path = root / "input.json"
            output_path = root / "output.json"
            input_path.write_bytes(b"{}")
            if private_root is None:
                private_root = root / "private-probe"
                private_root.mkdir(mode=0o700)
            private_context = nullcontext(str(private_root))
            protocols = protocol_values or (implementation, implementation)
            patches = (
                patch.object(gate, "_validate_probe_worker_input",
                             return_value=deepcopy(spec_value or spec)),
                patch.object(gate, "_performance_implementation_protocol",
                             side_effect=protocols),
                patch.object(gate, "short_temporary_directory",
                             return_value=private_context),
                patch.object(gate, "_candidate_performance_authority",
                             return_value=nullcontext(
                                 gate._CANDIDATE_PROBE_AUTHORITY_MODE
                             )),
                patch.object(gate, "_full_pipeline_probe",
                             return_value=deepcopy(pipeline_result or {})),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                if write_error is None:
                    code = gate._run_probe_worker(input_path, output_path)
                else:
                    with patch.object(
                        gate, "_write_json", side_effect=write_error,
                    ), redirect_stderr(io.StringIO()):
                        code = gate._run_probe_worker(input_path, output_path)
            response = (
                gate.json.loads(output_path.read_text(encoding="utf-8"))
                if output_path.exists() else None
            )
            return code, response

        code, response = invoke(pipeline_result={"value": 1})
        self.assertEqual(code, 0)
        self.assertEqual(response["status"], "passed")
        self.assertEqual(
            response["result"]["performance_authority_mode"],
            gate._CANDIDATE_PROBE_AUTHORITY_MODE,
        )

        provisional_spec = deepcopy(spec)
        provisional_spec["provisional_gate_path"] = "/provisional.json"
        code, response = invoke(spec_value=provisional_spec)
        self.assertEqual(code, 0)
        self.assertEqual(response["status"], "passed")

        mismatched = deepcopy(spec)
        mismatched["expected_implementation"][
            "generation_source_identity"
        ] = "f" * 64
        code, response = invoke(spec_value=mismatched)
        self.assertEqual(code, 1)
        self.assertEqual(response["status"], "failed")

        changed_after = deepcopy(implementation)
        changed_after["runtime_implementation_identity"] = "f" * 64
        code, response = invoke(protocol_values=(implementation, changed_after))
        self.assertEqual(code, 1)
        self.assertIn("changed during run", response["failure"]["detail"])

        with tempfile.TemporaryDirectory() as temporary:
            nonempty = Path(temporary)
            (nonempty / "sentinel").write_text("x", encoding="utf-8")
            code, response = invoke(private_root=nonempty)
        self.assertEqual(code, 1)
        self.assertIn("private empty directory", response["failure"]["detail"])

        with tempfile.TemporaryDirectory() as temporary:
            regular_file = Path(temporary) / "not-a-directory"
            regular_file.write_bytes(b"file")
            code, response = invoke(private_root=regular_file)
        self.assertEqual(code, 1)
        self.assertIn("private empty directory", response["failure"]["detail"])

        with tempfile.TemporaryDirectory() as temporary:
            insecure = Path(temporary) / "insecure"
            insecure.mkdir(mode=0o755)
            insecure.chmod(0o755)
            code, response = invoke(private_root=insecure)
        self.assertEqual(code, 1)
        self.assertIn("private empty directory", response["failure"]["detail"])

        code, response = invoke(write_error=OSError("output failed"))
        self.assertEqual(code, 1)
        self.assertIsNone(response)

    def test_candidate_authority_modes_binding_and_cleanup_matrix(self):
        import binary_pipeline

        implementation = self.implementation()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorded = root / "recorded.json"
            support = root / "support.json"
            provisional = root / "provisional.json"
            recorded.write_text(
                gate.json.dumps({"measurement_protocol": {}}), encoding="utf-8",
            )
            support.write_text(
                gate.json.dumps({"performance_gate": {"status": "passed"}}),
                encoding="utf-8",
            )
            provisional.write_bytes(b'{"provisional":true}\n')
            cleanup_bootstrap = Mock()
            cleanup_recapture = Mock()

            def contexts(binding_mode, *, provisional_path=None):
                return (
                    patch.object(binary_pipeline, "PERFORMANCE_GATE_PATH", recorded),
                    patch.object(binary_pipeline, "SUPPORT_MANIFEST_PATH", support),
                    patch.object(
                        binary_pipeline,
                        "_performance_authority_gate_binding",
                        return_value={"authority_mode": binding_mode},
                    ),
                    patch.object(
                        binary_pipeline,
                        "_cleanup_performance_measurement_state",
                        cleanup_bootstrap,
                    ),
                    patch.object(
                        binary_pipeline,
                        "_cleanup_performance_recapture_state",
                        cleanup_recapture,
                    ),
                    patch.object(
                        gate, "evaluate_provisional_gate",
                        return_value={"status": "passed", "issues": []},
                    ),
                )

            patches = contexts(gate._CANDIDATE_PROBE_AUTHORITY_MODE)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                with gate._candidate_performance_authority(
                    root / "bootstrap", implementation,
                ) as mode:
                    self.assertEqual(mode, gate._CANDIDATE_PROBE_AUTHORITY_MODE)
                    output_root = (
                        root / "bootstrap" / "full-pipeline-probe"
                    ).resolve()
                    output_root.mkdir(parents=True)
            cleanup_bootstrap.assert_called_with(output_root)
            self.assertFalse(output_root.exists())

            runtime_optional = deepcopy(implementation)
            runtime_optional["runtime_implementation_identity"] = ""
            support.write_text("{}", encoding="utf-8")
            recorded.write_text(
                gate.json.dumps({"measurement_protocol": {"existing": True}}),
                encoding="utf-8",
            )
            patches = contexts(gate._CANDIDATE_PROBE_AUTHORITY_MODE)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                with gate._candidate_performance_authority(
                    root / "bootstrap-no-runtime", runtime_optional,
                ) as mode:
                    self.assertEqual(mode, gate._CANDIDATE_PROBE_AUTHORITY_MODE)

            source_optional = deepcopy(runtime_optional)
            source_optional["source_implementation_identity"] = ""
            patches = contexts(gate._CANDIDATE_PROBE_AUTHORITY_MODE)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                with gate._candidate_performance_authority(
                    root / "bootstrap-no-source", source_optional,
                ) as mode:
                    self.assertEqual(mode, gate._CANDIDATE_PROBE_AUTHORITY_MODE)

            support.write_text(
                gate.json.dumps({"performance_gate": {"status": "passed"}}),
                encoding="utf-8",
            )
            patches = contexts(gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                with gate._candidate_performance_authority(
                    root / "recapture",
                    implementation,
                    provisional_gate_path=provisional,
                ) as mode:
                    self.assertEqual(
                        mode, gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE,
                    )
            self.assertTrue(cleanup_recapture.called)

            missing = root / "missing-provisional.json"
            patches = contexts(gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], self.assertRaisesRegex(
                gate.PerformanceGateError, "unreadable",
            ):
                with gate._candidate_performance_authority(
                    root / "missing", implementation,
                    provisional_gate_path=missing,
                ):
                    pass

            patches = contexts(gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patch.object(
                gate, "evaluate_provisional_gate",
                return_value={"status": "failed"},
            ), self.assertRaises(gate.PerformanceGateError) as raised:
                with gate._candidate_performance_authority(
                    root / "invalid-provisional", implementation,
                    provisional_gate_path=provisional,
                ):
                    pass
            self.assertEqual(
                raised.exception.failure["reason_code"],
                "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID",
            )

            patches = contexts(gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patch.object(
                gate, "evaluate_provisional_gate",
                return_value={"status": "failed", "issues": [{"detail": "x"}]},
            ), self.assertRaises(gate.PerformanceGateError) as raised:
                with gate._candidate_performance_authority(
                    root / "invalid-provisional-with-issues", implementation,
                    provisional_gate_path=provisional,
                ):
                    pass
            self.assertEqual(raised.exception.failure["issues"], [{"detail": "x"}])

            patches = contexts("wrong-mode")
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], self.assertRaisesRegex(
                gate.PerformanceGateError, "authority mode",
            ):
                with gate._candidate_performance_authority(
                    root / "wrong-binding", implementation,
                ):
                    pass

            external = root / "external"
            external.mkdir()
            sentinel = external / "sentinel"
            sentinel.write_text("unchanged", encoding="utf-8")
            symlink_root = root / "symlink-cleanup"
            patches = contexts(gate._CANDIDATE_PROBE_AUTHORITY_MODE)
            symlink_supported = True
            try:
                with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
                    with gate._candidate_performance_authority(
                        symlink_root, implementation,
                    ):
                        output_root = (
                            symlink_root / "full-pipeline-probe"
                        ).resolve(strict=False)
                        output_root.parent.mkdir(parents=True, exist_ok=True)
                        output_root.symlink_to(external, target_is_directory=True)
            except OSError:
                symlink_supported = False
            if symlink_supported:
                self.assertFalse(output_root.exists())
                self.assertFalse(output_root.is_symlink())
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")

            failed_cleanup_root = root / "failed-cleanup"
            patches = contexts(gate._CANDIDATE_PROBE_AUTHORITY_MODE)
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patch.object(
                gate.shutil, "rmtree",
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "cleanup failed",
            ):
                with gate._candidate_performance_authority(
                    failed_cleanup_root, implementation,
                ):
                    output_root = (
                        failed_cleanup_root / "full-pipeline-probe"
                    ).resolve()
                    output_root.mkdir(parents=True)

            dangling_root = root / "dangling-cleanup"
            dangling_output = (
                dangling_root / "full-pipeline-probe"
            ).resolve(strict=False)
            real_unlink = Path.unlink
            def keep_dangling(path_value, *args, **kwargs):
                if Path(path_value) == dangling_output:
                    return None
                return real_unlink(path_value, *args, **kwargs)
            patches = contexts(gate._CANDIDATE_PROBE_AUTHORITY_MODE)
            try:
                with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patch.object(
                    Path, "unlink", keep_dangling,
                ), self.assertRaisesRegex(
                    gate.PerformanceGateError, "cleanup failed",
                ):
                    with gate._candidate_performance_authority(
                        dangling_root, implementation,
                    ):
                        dangling_output.parent.mkdir(parents=True, exist_ok=True)
                        dangling_output.symlink_to(root / "missing-target")
            finally:
                if dangling_output.is_symlink():
                    real_unlink(dangling_output)

    def test_authority_preflight_private_root_and_exception_matrix(self):
        implementation = self.implementation()
        with patch.object(
            gate, "_candidate_performance_authority",
            return_value=nullcontext(gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE),
        ):
            gate._preflight_performance_authority(
                implementation, provisional_gate_path=Path("/provisional.json"),
            )

        injected = gate.PerformanceGateError("domain failure")
        with patch.object(
            gate, "_candidate_performance_authority", side_effect=injected,
        ), self.assertRaises(gate.PerformanceGateError) as raised:
            gate._preflight_performance_authority(
                implementation, provisional_gate_path=Path("/provisional.json"),
            )
        self.assertIs(raised.exception, injected)

        with patch.object(
            gate, "_candidate_performance_authority",
            side_effect=RuntimeError("unexpected failure"),
        ), self.assertRaises(gate.PerformanceGateError) as raised:
            gate._preflight_performance_authority(
                implementation, provisional_gate_path=Path("/provisional.json"),
            )
        self.assertEqual(
            raised.exception.failure["reason_code"],
            "BINARY_PERFORMANCE_AUTHORITY_PREFLIGHT_FAILED",
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invalid_roots = []
            regular = root / "regular"
            regular.write_bytes(b"file")
            invalid_roots.append(("regular", regular))
            insecure = root / "insecure"
            insecure.mkdir(mode=0o755)
            insecure.chmod(0o755)
            invalid_roots.append(("insecure", insecure))
            nonempty = root / "nonempty"
            nonempty.mkdir(mode=0o700)
            (nonempty / "sentinel").write_bytes(b"x")
            invalid_roots.append(("nonempty", nonempty))
            for label, invalid_root in invalid_roots:
                with self.subTest(label=label), patch.object(
                    gate, "short_temporary_directory",
                    return_value=nullcontext(str(invalid_root)),
                ), patch.object(
                    gate, "_candidate_performance_authority",
                    side_effect=AssertionError("candidate must not start"),
                ), self.assertRaises(gate.PerformanceGateError):
                    gate._preflight_performance_authority(
                        implementation,
                        provisional_gate_path=Path("/provisional.json"),
                    )

    def test_analysis_cache_mode_preconditions(self):
        artifacts = []
        root = Path("/unused-root")
        cache = Path("/unused-cache")
        asm = Path("/unused-asm.jar")
        reached_expensive_work = RuntimeError("reached expensive work")

        with patch.object(
            gate, "_physical_directory_identity", side_effect=((1,), (2,)),
        ), self.assertRaisesRegex(
            gate.PerformanceGateError, "changed before cold cleanup",
        ):
            gate._analyze_once(
                artifacts, root=root, cache_root=cache, asm_jar=asm, warm=False,
            )

        with patch.object(
            gate, "_physical_directory_identity", return_value=None,
        ), self.assertRaisesRegex(
            gate.PerformanceGateError, "warm performance snapshot cache is absent",
        ):
            gate._analyze_once(
                artifacts, root=root, cache_root=cache, asm_jar=asm, warm=True,
            )

        with patch.object(
            gate, "_physical_directory_identity", side_effect=((1,), (1,)),
        ), patch.object(
            gate.shutil, "rmtree",
        ) as remove_cache, patch.object(
            gate, "_jdk_home", side_effect=reached_expensive_work,
        ), self.assertRaises(RuntimeError) as raised:
            gate._analyze_once(
                artifacts, root=root, cache_root=cache, asm_jar=asm, warm=False,
            )
        self.assertIs(raised.exception, reached_expensive_work)
        remove_cache.assert_called_once_with(cache)

        with patch.object(
            gate, "_physical_directory_identity", return_value=(1,),
        ), patch.object(
            gate, "_jdk_home", side_effect=reached_expensive_work,
        ), self.assertRaises(RuntimeError) as raised:
            gate._analyze_once(
                artifacts, root=root, cache_root=cache, asm_jar=asm, warm=True,
            )
        self.assertIs(raised.exception, reached_expensive_work)

    def test_full_pipeline_evidence_empty_and_populated_histograms(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generation = root / "generation"
            generation.mkdir()
            validation_path = root / "validation.json"

            for side, count in (("base", 2), ("current", 3)):
                with closing(gate.sqlite3.connect(
                    generation / f"{side}_binary_facts.sqlite"
                )) as connection:
                    connection.execute("CREATE TABLE classes (name TEXT)")
                    connection.executemany(
                        "INSERT INTO classes(name) VALUES (?)",
                        [(f"C{index}",) for index in range(count)],
                    )
                    connection.commit()

            validation_path.write_text("{}", encoding="utf-8")
            (generation / "binary_decisions.json").write_text(
                gate.json.dumps({"authoritative_change_facts": []}),
                encoding="utf-8",
            )
            (generation / "binary_formal_results.json").write_text(
                gate.json.dumps({"by_api": []}), encoding="utf-8",
            )
            empty = gate._full_pipeline_evidence({
                "generation_directory": str(generation),
                "validation_result_path": str(validation_path),
            })
            self.assertEqual(empty["base_class_count"], 2)
            self.assertEqual(empty["current_class_count"], 3)
            self.assertEqual(empty["validation_status"], "")
            self.assertEqual(empty["validation_issue_count"], 0)
            self.assertEqual(empty["authoritative_member_change_kind_counts"], {})

            validation_path.write_text(
                gate.json.dumps({"status": "passed", "issue_count": 1}),
                encoding="utf-8",
            )
            (generation / "binary_decisions.json").write_text(
                gate.json.dumps({
                    "authoritative_change_facts": [
                        {"fact_scope": {"member_change_kind": "changed"}},
                        {"fact_scope": {}},
                        {},
                    ],
                }),
                encoding="utf-8",
            )
            (generation / "binary_formal_results.json").write_text(
                gate.json.dumps({
                    "by_api": [
                        {
                            "reachability_status": "reachable",
                            "impact_conclusion": "affected",
                        },
                        {},
                    ],
                }),
                encoding="utf-8",
            )
            populated = gate._full_pipeline_evidence({
                "generation_directory": str(generation),
                "validation_result_path": str(validation_path),
            })
            self.assertEqual(populated["validation_status"], "passed")
            self.assertEqual(populated["validation_issue_count"], 1)
            self.assertEqual(populated["authoritative_change_fact_count"], 3)
            self.assertEqual(
                populated["authoritative_member_change_kind_counts"],
                {"None": 2, "changed": 1},
            )
            self.assertEqual(populated["formal_api_result_count"], 2)

    def test_full_pipeline_probe_selection_state_and_metric_fallback_matrix(self):
        import binary_output
        import binary_pipeline

        base = [
            {"path": f"/base-{index}.jar", "sha256": chr(97 + index) * 64}
            for index in range(2)
        ]
        current = [deepcopy(item) for item in base]
        evidence = {
            "class_count": 2,
            "base_class_count": 2,
            "current_class_count": 2,
            "validation_status": "passed",
            "validation_issue_count": 0,
            "authoritative_change_fact_count": 0,
            "authoritative_member_change_kind_counts": {},
            "formal_api_result_count": 0,
            "formal_reachability_status_counts": {},
            "formal_impact_conclusion_counts": {},
        }

        def pipeline_result(*, activations=1, optional_metrics=True):
            phases = [
                {
                    "phase": "validated_generation_activation",
                    "elapsed_seconds": 0.1,
                    "peak_rss_bytes": 10,
                    "completed_child_peak_rss_bytes": 5,
                    "activation_authority_mode": (
                        gate._CANDIDATE_PROBE_AUTHORITY_MODE
                    ),
                    "publication_deferred": False,
                    "checkpoint_retained": False,
                    "activation_candidate_discarded": True,
                }
                for _index in range(activations)
            ]
            result = {
                "total_elapsed_seconds": 1.0,
                "total_elapsed_scope": "current_pipeline_attempt",
                "phase_timings_scope": "current_pipeline_attempt",
                "phase_timings": phases,
                "cache_metrics": {
                    "classfile_parser_invocations": 2,
                    "artifact_snapshot_hits": 0,
                },
            }
            if optional_metrics:
                result.update({
                    "peak_rss_bytes": 10,
                    "performance_authority_gate_binding": {"binding": True},
                })
                result["cache_metrics"].update({
                    "artifact_snapshot_disk_hits": 0,
                    "artifact_snapshot_memory_hits": 0,
                })
            return result

        def invoke(
            *, artifacts=base, current_artifacts=current, jar_limit=None,
            result=None, active=None, pending=None, checkpoint_absent=True,
        ):
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
            submitted = {}
            def run_pipeline(config, **_kwargs):
                submitted.update(config)
                return deepcopy(result or pipeline_result())
            with patch.object(
                binary_pipeline, "run_pipeline", side_effect=run_pipeline,
            ), patch.object(
                binary_pipeline, "_filesystem_entry_absent",
                return_value=checkpoint_absent,
            ), patch.object(
                binary_output, "read_active_binary_generation",
                return_value=active,
            ), patch.object(
                binary_output, "read_pending_binary_generation",
                return_value=pending,
            ), patch.object(
                gate, "_full_pipeline_evidence", return_value=evidence,
            ), patch.object(
                gate, "_jdk_home", return_value=Path("/jdk"),
            ), patch.object(
                gate, "_timing_metrics", return_value={
                    "end_to_end_seconds": 2.0,
                    "cpu_seconds": 1.0,
                    "average_cpu_cores": 0.5,
                },
            ), patch.object(
                gate, "_rss_bytes", return_value=20,
            ):
                output = gate._full_pipeline_probe(
                    artifacts,
                    current_artifacts=current_artifacts,
                    root=root,
                    asm_jar=Path("/asm.jar"),
                    classes_per_jar=2,
                    jar_limit=jar_limit,
                )
            return output, submitted

        selected, submitted = invoke(jar_limit=1)
        self.assertEqual(selected["jar_count"], 1)
        self.assertEqual(len(submitted["base"]["artifacts"]), 1)
        identical, _ = invoke(current_artifacts=None)
        self.assertEqual(
            identical["comparison"], "identical-base-current-cold-output",
        )
        changed = deepcopy(current)
        changed[0]["sha256"] = "f" * 64
        nonidentical, _ = invoke(current_artifacts=changed)
        self.assertEqual(
            nonidentical["comparison"],
            "nonidentical-base-current-cold-output",
        )
        fallback_metrics, _ = invoke(
            result=pipeline_result(optional_metrics=False),
        )
        self.assertEqual(fallback_metrics["pipeline_reported_peak_rss_bytes"], 0)
        self.assertEqual(fallback_metrics["pipeline_performance_authority_binding"], {})
        self.assertEqual(fallback_metrics["artifact_snapshot_disk_hits"], 0)
        self.assertEqual(fallback_metrics["artifact_snapshot_memory_hits"], 0)
        phase_fallback_result = pipeline_result()
        phase_fallback_result["phase_timings"][0].pop("peak_rss_bytes")
        phase_fallback_result["phase_timings"][0].pop(
            "completed_child_peak_rss_bytes"
        )
        phase_fallback, _ = invoke(result=phase_fallback_result)
        self.assertEqual(
            phase_fallback["phase_peak_rss_bytes"][
                "validated_generation_activation"
            ],
            0,
        )
        populated_optional_result = pipeline_result()
        populated_optional_result["phase_timings"].insert(0, {
            "phase": "independent_validation",
            "elapsed_seconds": 0.2,
            "peak_rss_bytes": 5,
            "completed_child_peak_rss_bytes": 6,
        })
        populated_optional_result["cache_metrics"].update({
            "artifact_snapshot_disk_hits": 1,
            "artifact_snapshot_memory_hits": 2,
        })
        populated_optional, _ = invoke(result=populated_optional_result)
        self.assertEqual(populated_optional["artifact_snapshot_disk_hits"], 1)
        self.assertEqual(populated_optional["artifact_snapshot_memory_hits"], 2)

        with self.assertRaisesRegex(gate.PerformanceGateError, "counts must match"):
            invoke(current_artifacts=current[:1])
        for activations in (0, 2):
            with self.subTest(activations=activations), self.assertRaisesRegex(
                gate.PerformanceGateError, "activation timing record",
            ):
                invoke(result=pipeline_result(activations=activations))
        for label, state in (
            ("active", {"active": object()}),
            ("pending", {"pending": object()}),
            ("checkpoint", {"checkpoint_absent": False}),
        ):
            with self.subTest(state=label), self.assertRaisesRegex(
                gate.PerformanceGateError, "left publication or checkpoint state",
            ):
                invoke(**state)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_root = root / "full-pipeline-probe"
            output_root.mkdir()
            with self.assertRaisesRegex(
                gate.PerformanceGateError, "already exists",
            ):
                gate._full_pipeline_probe(
                    base,
                    current_artifacts=current,
                    root=root,
                    asm_jar=Path("/asm.jar"),
                    classes_per_jar=2,
                )
            output_root.rmdir()
            try:
                output_root.symlink_to(root / "missing", target_is_directory=True)
            except OSError:
                output_root = None
            if output_root is not None:
                try:
                    with self.assertRaisesRegex(
                        gate.PerformanceGateError, "already exists",
                    ):
                        gate._full_pipeline_probe(
                            base,
                            current_artifacts=current,
                            root=root,
                            asm_jar=Path("/asm.jar"),
                            classes_per_jar=2,
                        )
                finally:
                    output_root.unlink()

    def test_dataset_cache_validation_rebuild_and_size_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = gate.build_dataset(
                root, jar_count=2, classes_per_jar=1,
            )
            manifest_path = root / "dataset" / "manifest.json"
            with patch.object(
                gate, "_compile_template",
                side_effect=AssertionError("valid cache must be reused"),
            ):
                cached = gate.build_dataset(
                    root, jar_count=2, classes_per_jar=1,
                )
            self.assertEqual(cached, artifacts)

            mutations = []
            base_manifest = gate.json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            missing_field = deepcopy(base_manifest)
            del missing_field["schema"]
            mutations.append(("fields", missing_field))
            for label, field, value in (
                ("schema", "schema", "wrong"),
                ("jar-type", "jar_count", True),
                ("jar-value", "jar_count", 1),
                ("classes-type", "classes_per_jar", True),
                ("classes-value", "classes_per_jar", 2),
                ("class-count-type", "class_count", True),
                ("class-count-value", "class_count", 3),
                ("template", "base_template_sha256", "0" * 64),
            ):
                item = deepcopy(base_manifest)
                item[field] = value
                mutations.append((label, item))
            artifact_shape = deepcopy(base_manifest)
            artifact_shape["artifacts"] = {}
            mutations.append(("artifact-shape", artifact_shape))
            artifact_count = deepcopy(base_manifest)
            artifact_count["artifacts"] = artifact_count["artifacts"][:1]
            mutations.append(("artifact-count", artifact_count))
            artifact_object = deepcopy(base_manifest)
            artifact_object["artifacts"][0] = []
            mutations.append(("artifact-object", artifact_object))
            artifact_path = deepcopy(base_manifest)
            artifact_path["artifacts"][0]["path"] = str(root / "outside.jar")
            mutations.append(("artifact-path", artifact_path))
            artifact_sha = deepcopy(base_manifest)
            artifact_sha["artifacts"][0]["sha256"] = "bad"
            mutations.append(("artifact-sha", artifact_sha))

            for label, manifest in mutations:
                manifest_path.write_text(
                    gate.json.dumps(manifest), encoding="utf-8",
                )
                with self.subTest(label=label), patch.object(
                    gate, "_compile_template", wraps=gate._compile_template,
                ) as compile_template:
                    rebuilt = gate.build_dataset(
                        root, jar_count=2, classes_per_jar=1,
                    )
                self.assertEqual(len(rebuilt), 2)
                compile_template.assert_called_once()

            manifest_path.write_bytes(b"not-json")
            rebuilt = gate.build_dataset(root, jar_count=2, classes_per_jar=1)
            self.assertEqual(len(rebuilt), 2)

            with patch.object(
                gate, "_validate_probe_worker_artifacts", return_value=[],
            ), patch.object(
                gate, "_compile_template", wraps=gate._compile_template,
            ) as compile_template:
                rebuilt = gate.build_dataset(
                    root, jar_count=2, classes_per_jar=1,
                )
            self.assertEqual(len(rebuilt), 2)
            compile_template.assert_called_once()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "dataset" / "manifest.json"
            real_lstat = os.lstat
            def fail_manifest(path_value):
                if Path(path_value) == manifest:
                    raise OSError("inspection failed")
                return real_lstat(path_value)
            with patch.object(
                gate.os, "lstat", side_effect=fail_manifest,
            ), self.assertRaisesRegex(
                gate.PerformanceGateError, "cannot be inspected",
            ):
                gate.build_dataset(root, jar_count=1, classes_per_jar=1)

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            gate, "_physical_directory_identity",
            side_effect=((1,), (2,)),
        ), self.assertRaisesRegex(
            gate.PerformanceGateError, "changed before rebuild",
        ):
            gate.build_dataset(
                Path(temporary), jar_count=1, classes_per_jar=1,
            )

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            gate, "_compile_template", return_value=b"p/C000000",
        ), self.assertRaisesRegex(
            gate.PerformanceGateError, "owner length overflow",
        ):
            gate.build_dataset(
                Path(temporary), jar_count=1000, classes_per_jar=1001,
            )

    def test_changed_dataset_empty_valid_and_size_boundary_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                gate.PerformanceGateError, "at least one artifact",
            ):
                gate.build_changed_current_artifacts(
                    root, [], classes_per_jar=1,
                )
            artifacts = gate.build_dataset(
                root, jar_count=1, classes_per_jar=1,
            )
            original = deepcopy(artifacts)
            current = gate.build_changed_current_artifacts(
                root, artifacts, classes_per_jar=1,
            )
            self.assertEqual(artifacts, original)
            self.assertNotEqual(current[0]["sha256"], artifacts[0]["sha256"])
            self.assertEqual(current[0]["first_class_index"], 0)

            overflow = deepcopy(artifacts)
            overflow[0]["first_class_index"] = 1_000_000
            with self.assertRaisesRegex(
                gate.PerformanceGateError, "owner length overflow",
            ):
                gate.build_changed_current_artifacts(
                    root, overflow, classes_per_jar=1,
                )

    def test_recorded_gate_outer_shape_and_live_identity_matrix(self):
        passed = {
            "schema": "verification",
            "status": "passed",
            "issue_count": 0,
            "issues": [],
        }
        with patch.object(
            gate, "_evaluate_recorded_gate", return_value=passed,
        ) as evaluator:
            self.assertEqual(gate.evaluate_recorded_gate({}), passed)
        evaluator.assert_called_once()

        non_mapping = gate.evaluate_recorded_gate([])
        self.assertEqual(
            non_mapping["issues"][0]["reason_code"],
            "BINARY_PERFORMANCE_RECORDED_ROOT_INVALID",
        )
        nonfinite = gate.evaluate_recorded_gate({
            "nested": {"values": [1, (2, math.inf)]},
        })
        self.assertEqual(
            nonfinite["issues"][0]["reason_code"],
            "BINARY_PERFORMANCE_RECORDED_NONFINITE_NUMBER",
        )
        finite_nested = {"nested": {"values": [1.5, (2, "x")]}}
        with patch.object(
            gate, "_evaluate_recorded_gate", return_value=passed,
        ):
            self.assertEqual(
                gate.evaluate_recorded_gate(finite_nested)["status"], "passed",
            )
        for marker, reason in (
            (
                "measurement_bootstrap",
                "BINARY_PERFORMANCE_RECORDED_BOOTSTRAP_FORBIDDEN",
            ),
            (
                "measurement_provisional",
                "BINARY_PERFORMANCE_RECORDED_PROVISIONAL_FORBIDDEN",
            ),
        ):
            result = gate.evaluate_recorded_gate({marker: {}})
            self.assertEqual(result["issues"][0]["reason_code"], reason)

        shape_cases = []
        for field in (
            "measurement_protocol", "recorded_measurements", "thresholds",
            "accuracy_invariants",
        ):
            shape_cases.append((f"top-{field}", {field: []}))
        for container_name, fields in (
            (
                "measurement_protocol",
                (
                    "machine", "implementation", "sample_runs", "tool_versions",
                    "full_pipeline_probe", "changed_full_pipeline_probe",
                ),
            ),
            (
                "recorded_measurements",
                (
                    "cold_stage_seconds", "stage_seconds", "full_pipeline_probe",
                    "changed_full_pipeline_probe",
                ),
            ),
            (
                "thresholds",
                (
                    "full_pipeline_phase_seconds",
                    "changed_full_pipeline_phase_seconds", "stage_p95_seconds",
                ),
            ),
        ):
            for field in fields:
                shape_cases.append((
                    f"{container_name}-{field}",
                    {container_name: {field: []}},
                ))
        for field in (
            "warm_end_to_end_samples_seconds",
            "warm_cpu_seconds_samples",
            "warm_average_cpu_cores_samples",
            "warm_parser_invocations_samples",
            "warm_cache_hits_samples",
            "warm_peak_rss_bytes_samples",
            "warm_stage_seconds_samples",
        ):
            shape_cases.append((
                f"array-{field}",
                {"recorded_measurements": {field: {}}},
            ))
        shape_cases.append((
            "dataset-artifacts",
            {"measurement_protocol": {"dataset_artifact_identities": {}}},
        ))
        for probe_name in (
            "full_pipeline_probe", "changed_full_pipeline_probe",
        ):
            shape_cases.append((
                f"includes-{probe_name}",
                {"measurement_protocol": {probe_name: {"includes": {}}}},
            ))
        for label, value in shape_cases:
            with self.subTest(label=label):
                result = gate.evaluate_recorded_gate(value)
                self.assertEqual(
                    result["issues"][0]["reason_code"],
                    "BINARY_PERFORMANCE_RECORDED_STRUCTURE_INVALID",
                )

        valid_optional_arrays = {
            "measurement_protocol": {
                "dataset_artifact_identities": [],
                "full_pipeline_probe": {"includes": []},
                "changed_full_pipeline_probe": {"includes": ()},
            },
            "recorded_measurements": {
                field: []
                for field in (
                    "warm_end_to_end_samples_seconds",
                    "warm_cpu_seconds_samples",
                    "warm_average_cpu_cores_samples",
                    "warm_parser_invocations_samples",
                    "warm_cache_hits_samples",
                    "warm_peak_rss_bytes_samples",
                    "warm_stage_seconds_samples",
                )
            },
        }
        with patch.object(
            gate, "_evaluate_recorded_gate", return_value=passed,
        ):
            self.assertEqual(
                gate.evaluate_recorded_gate(valid_optional_arrays)["status"],
                "passed",
            )

        implementation = self.implementation()
        with patch.object(
            gate, "_evaluate_recorded_gate", return_value=passed,
        ):
            self.assertEqual(
                gate.evaluate_recorded_gate(
                    {}, _current_source_implementation=implementation,
                )["status"],
                "passed",
            )
            self.assertEqual(
                gate.evaluate_recorded_gate(
                    {},
                    _current_source_implementation=implementation,
                    _require_live_runtime_implementation=True,
                )["status"],
                "passed",
            )
        invalid_implementations = []
        invalid_sha = deepcopy(implementation)
        invalid_sha["generation_source_identity"] = "bad"
        invalid_implementations.append((invalid_sha, False))
        source_mismatch = deepcopy(implementation)
        source_mismatch["source_implementation_identity"] = "f" * 64
        invalid_implementations.append((source_mismatch, False))
        runtime_mismatch = deepcopy(implementation)
        runtime_mismatch["runtime_implementation_identity"] = "f" * 64
        invalid_implementations.append((runtime_mismatch, True))
        for value, require_runtime in invalid_implementations:
            result = gate.evaluate_recorded_gate(
                {},
                _current_source_implementation=value,
                _require_live_runtime_implementation=require_runtime,
            )
            self.assertEqual(
                result["issues"][0]["reason_code"],
                "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_UNAVAILABLE",
            )

        with patch.object(
            gate, "_evaluate_recorded_gate", side_effect=ValueError("malformed"),
        ):
            result = gate.evaluate_recorded_gate({})
        self.assertEqual(
            result["issues"][0]["reason_code"],
            "BINARY_PERFORMANCE_RECORDED_STRUCTURE_INVALID",
        )

    def test_recorded_gate_replay_accepts_independently_checked_fixture(self):
        evidence = self.recorded_gate_fixture()
        implementation = evidence["measurement_protocol"]["implementation"]
        for require_runtime in (False, True):
            with self.subTest(require_runtime=require_runtime):
                result = gate._evaluate_recorded_gate(
                    evidence,
                    current_source_implementation=implementation,
                    require_live_runtime_implementation=require_runtime,
                )
                self.assertEqual(result["status"], "passed", result["issues"])
                self.assertEqual(result["issue_count"], 0)
                self.assertTrue(result["recorded_measurements_replayed"])

    def test_recorded_gate_replay_rejects_empty_nested_evidence_totally(self):
        result = gate._evaluate_recorded_gate(
            {}, current_source_implementation={},
        )
        self.assertEqual(result["status"], "failed")
        reason_codes = {issue["reason_code"] for issue in result["issues"]}
        self.assertIn("BINARY_PERFORMANCE_RECORDED_POLICY_MISMATCH", reason_codes)
        self.assertIn("BINARY_PERFORMANCE_RECORDED_DATASET_INVALID", reason_codes)
        self.assertIn("BINARY_PERFORMANCE_RECORDED_CPU_INVALID", reason_codes)
        self.assertIn("BINARY_PERFORMANCE_RECORDED_REPLAY_INVALID", reason_codes)
        self.assertTrue(result["recorded_measurements_replayed"])

    def test_recorded_gate_reference_policy_and_live_resolution_matrix(self):
        evidence = self.recorded_gate_fixture()
        implementation = evidence["measurement_protocol"]["implementation"]

        class NonMappingReference:
            def __init__(self, value):
                self.value = value

            def keys(self):
                return self.value.keys()

            def __getitem__(self, key):
                return self.value[key]

            def get(self, key, default=None):
                return self.value.get(key, default)

        class FalseyReference(dict):
            def __bool__(self):
                return False

        base_policy = gate.release_policy()
        references = []
        references.append((
            "non-mapping",
            NonMappingReference(deepcopy(base_policy["reference_implementation"])),
        ))
        extra_key = deepcopy(base_policy["reference_implementation"])
        extra_key["unexpected"] = "value"
        references.append(("unexpected-key", extra_key))
        bad_schema = deepcopy(base_policy["reference_implementation"])
        bad_schema["schema"] = "wrong"
        references.append(("schema", bad_schema))
        bad_hash = deepcopy(base_policy["reference_implementation"])
        bad_hash["pipeline_generation_implementation_identity"] = "bad"
        references.append(("hash-shape", bad_hash))
        zero_hash = deepcopy(base_policy["reference_implementation"])
        zero_hash["validator_implementation_identity"] = "0" * 64
        references.append(("zero-hash", zero_hash))
        falsey = FalseyReference(base_policy["reference_implementation"])
        falsey["schema"] = "wrong"
        references.append(("falsey-mapping", falsey))
        for label, reference in references:
            policy = deepcopy(base_policy)
            policy["reference_implementation"] = reference
            with self.subTest(reference=label), patch.object(
                gate, "release_policy", return_value=policy,
            ):
                result = gate._evaluate_recorded_gate(
                    evidence, current_source_implementation=implementation,
                )
            self.assertEqual(result["status"], "failed")
            self.assertIn(
                "BINARY_PERFORMANCE_REFERENCE_IMPLEMENTATION_INVALID",
                {issue["reason_code"] for issue in result["issues"]},
            )

        for require_runtime in (False, True):
            with self.subTest(resolve=require_runtime), patch.object(
                gate, "resolve_asm_jar", return_value=Path("/asm.jar"),
            ) as resolver, patch.object(
                gate, "_performance_implementation_protocol",
                return_value=implementation,
            ) as implementation_protocol:
                result = gate._evaluate_recorded_gate(
                    evidence,
                    current_source_implementation=None,
                    require_live_runtime_implementation=require_runtime,
                )
            self.assertEqual(result["status"], "passed", result["issues"])
            implementation_protocol.assert_called_once_with(
                Path("/asm.jar") if require_runtime else None,
                include_runtime=require_runtime,
            )
            self.assertEqual(resolver.called, require_runtime)

        with patch.object(
            gate, "_performance_implementation_protocol",
            side_effect=RuntimeError("implementation unavailable"),
        ):
            result = gate._evaluate_recorded_gate(
                evidence, current_source_implementation=None,
            )
        self.assertIn(
            "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_UNAVAILABLE",
            {issue["reason_code"] for issue in result["issues"]},
        )

    def test_recorded_gate_dataset_numeric_and_cpu_mutation_matrix(self):
        base = self.recorded_gate_fixture()
        implementation = base["measurement_protocol"]["implementation"]

        def rejected(label, mutate, reason_code, field=None):
            evidence = deepcopy(base)
            mutate(evidence)
            result = gate._evaluate_recorded_gate(
                evidence, current_source_implementation=implementation,
            )
            self.assertEqual(result["status"], "failed", label)
            matching = [
                issue for issue in result["issues"]
                if issue["reason_code"] == reason_code
                and (field is None or issue.get("field") == field)
            ]
            self.assertTrue(matching, (label, result["issues"]))

        mutations = (
            (
                "blank-metadata",
                lambda value: value.__setitem__("rerun_command", "  "),
                "BINARY_PERFORMANCE_RECORDED_METADATA_INVALID",
                "rerun_command",
            ),
            (
                "invalid-artifact-hash",
                lambda value: value["measurement_protocol"][
                    "dataset_artifact_identities"
                ].__setitem__(1, "bad"),
                "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
                "dataset_artifact_identities",
            ),
            (
                "changed-artifact-reuses-base",
                lambda value: value["measurement_protocol"][
                    "changed_full_pipeline_probe"
                ].__setitem__(
                    "current_artifact_identity",
                    value["measurement_protocol"][
                        "dataset_artifact_identities"
                    ][0],
                ),
                "BINARY_PERFORMANCE_RECORDED_DATASET_INVALID",
                "changed_full_pipeline_probe.current_artifact_identity",
            ),
            (
                "invalid-warm-peak-after-valid",
                lambda value: value["recorded_measurements"].__setitem__(
                    "warm_peak_rss_bytes_samples", [1, -1],
                ),
                "BINARY_PERFORMANCE_RECORDED_NUMERIC_INVALID",
                "warm_peak_rss_bytes_samples",
            ),
            (
                "decreasing-lifecycle-rss",
                lambda value: value["recorded_measurements"].update({
                    "warmup_peak_rss_bytes": 1,
                    "cold_peak_rss_bytes": 2,
                    "warm_peak_rss_bytes_samples": [3, 2],
                    "legacy_peak_rss_bytes": 4,
                }),
                "BINARY_PERFORMANCE_RECORDED_RSS_INVALID",
                "cold_warm_legacy_peak_rss_lifecycle",
            ),
            (
                "warm-sample-without-cpu-arrays",
                lambda value: value["recorded_measurements"].update({
                    "warm_cpu_seconds_samples": [],
                    "warm_average_cpu_cores_samples": [],
                }),
                "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
                "warm[0]",
            ),
            (
                "boolean-warmup-cpu",
                lambda value: value["recorded_measurements"].__setitem__(
                    "warmup_cpu_seconds", True,
                ),
                "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
                "warmup",
            ),
            (
                "unrecorded-cpu-status",
                lambda value: value["recorded_measurements"].__setitem__(
                    "cpu_measurement_status", "unavailable",
                ),
                "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
                "cpu_measurement_status",
            ),
            (
                "boolean-cold-wall",
                lambda value: value["recorded_measurements"].__setitem__(
                    "cold_end_to_end_seconds", True,
                ),
                "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
                "cold",
            ),
            (
                "boolean-total-wall",
                lambda value: value["recorded_measurements"].__setitem__(
                    "total_measured_wall_seconds", True,
                ),
                "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
                "total_measured_cpu",
            ),
            (
                "boolean-derived-value",
                lambda value: value["recorded_measurements"].__setitem__(
                    "bytes_per_class", True,
                ),
                "BINARY_PERFORMANCE_RECORDED_DERIVATION_INVALID",
                "bytes_per_class",
            ),
        )
        for label, mutate, reason_code, field in mutations:
            with self.subTest(label=label):
                rejected(label, mutate, reason_code, field)

    def test_recorded_gate_probe_isolation_rss_and_conservation_matrix(self):
        base = self.recorded_gate_fixture()
        implementation = base["measurement_protocol"]["implementation"]
        source_identity = implementation["source_implementation_identity"]

        def rejected(label, mutate, reason_code, field=None):
            evidence = deepcopy(base)
            mutate(evidence)
            result = gate._evaluate_recorded_gate(
                evidence, current_source_implementation=implementation,
            )
            self.assertEqual(result["status"], "failed", label)
            matching = [
                issue for issue in result["issues"]
                if issue["reason_code"] == reason_code
                and (field is None or issue.get("field") == field)
            ]
            self.assertTrue(matching, (label, result["issues"]))

        first_probe = "full_pipeline_probe"
        second_probe = "changed_full_pipeline_probe"

        def decreasing_phase_peaks(value):
            phases = list(gate.FULL_PIPELINE_PHASES)
            peaks = {phase: index + 10 for index, phase in enumerate(phases)}
            peaks[phases[1]] = 1
            value["recorded_measurements"][first_probe][
                "phase_peak_rss_bytes"
            ] = peaks

        def duplicate_process(value):
            probes = value["recorded_measurements"]
            probes[second_probe]["process_id"] = probes[first_probe]["process_id"]

        def inconsistent_binding(value):
            value["recorded_measurements"][second_probe][
                "pipeline_performance_authority_binding"
            ] = self.authority_binding(
                source_identity,
                mode=gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE,
                salt="b",
            )

        mutations = (
            (
                "negative-validation-count",
                lambda value: value["recorded_measurements"][first_probe].__setitem__(
                    "validation_issue_count", -1,
                ),
                "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                f"{first_probe}.validation_issue_count.type",
            ),
            (
                "zero-process-id",
                lambda value: value["recorded_measurements"][first_probe].__setitem__(
                    "process_id", 0,
                ),
                "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                f"{first_probe}.process_id",
            ),
            (
                "nonfinite-probe-wall",
                lambda value: value["recorded_measurements"][first_probe].__setitem__(
                    "end_to_end_seconds", math.inf,
                ),
                "BINARY_PERFORMANCE_RECORDED_PHASE_INVALID",
                f"{first_probe}.phase_total",
            ),
            (
                "decreasing-phase-rss",
                decreasing_phase_peaks,
                "BINARY_PERFORMANCE_RECORDED_RSS_INVALID",
                f"{first_probe}.phase_peak_rss_bytes",
            ),
            (
                "invalid-raw-peak-after-valid",
                lambda value: value["recorded_measurements"][first_probe].update({
                    "pipeline_reported_peak_rss_bytes": 1,
                    "post_pipeline_peak_rss_bytes": -1,
                }),
                "BINARY_PERFORMANCE_RECORDED_RSS_INVALID",
                f"{first_probe}.raw_peak_rss_bytes",
            ),
            (
                "boolean-pipeline-wall",
                lambda value: value["recorded_measurements"][first_probe].__setitem__(
                    "pipeline_reported_seconds", True,
                ),
                "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                f"{first_probe}.pipeline_reported_seconds",
            ),
            (
                "missing-phase-total-with-valid-wall",
                lambda value: value["recorded_measurements"][first_probe][
                    "phase_seconds"
                ].__setitem__(gate.FULL_PIPELINE_PHASES[0], "bad"),
                "BINARY_PERFORMANCE_RECORDED_PHASE_INVALID",
                f"{first_probe}.phase_seconds",
            ),
            (
                "cache-component-invalid-after-valid",
                lambda value: value["recorded_measurements"][first_probe].update({
                    "artifact_snapshot_hits": 1,
                    "artifact_snapshot_disk_hits": 0,
                    "artifact_snapshot_memory_hits": -1,
                }),
                "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
                f"{first_probe}.artifact_snapshot_hits",
            ),
            (
                "cache-conservation-mismatch",
                lambda value: value["recorded_measurements"][first_probe].update({
                    "artifact_snapshot_hits": 1,
                    "artifact_snapshot_disk_hits": 0,
                    "artifact_snapshot_memory_hits": 0,
                }),
                "BINARY_PERFORMANCE_RECORDED_CACHE_INVALID",
                f"{first_probe}.artifact_snapshot_hits",
            ),
            (
                "histogram-invalid-key-after-valid",
                lambda value: value["recorded_measurements"][first_probe].update({
                    "authoritative_member_change_kind_counts": {"valid": 0, "": 0},
                    "authoritative_change_fact_count": 0,
                }),
                "BINARY_PERFORMANCE_RECORDED_CONSERVATION_INVALID",
                f"{first_probe}.authoritative_member_change_kind_counts",
            ),
            (
                "histogram-negative-expected-total",
                lambda value: value["recorded_measurements"][first_probe].update({
                    "authoritative_member_change_kind_counts": {"valid": 0},
                    "authoritative_change_fact_count": -1,
                }),
                "BINARY_PERFORMANCE_RECORDED_CONSERVATION_INVALID",
                f"{first_probe}.authoritative_member_change_kind_counts",
            ),
            (
                "histogram-sum-mismatch",
                lambda value: value["recorded_measurements"][first_probe].update({
                    "authoritative_member_change_kind_counts": {"valid": 1},
                    "authoritative_change_fact_count": 0,
                }),
                "BINARY_PERFORMANCE_RECORDED_CONSERVATION_INVALID",
                f"{first_probe}.authoritative_member_change_kind_counts",
            ),
            (
                "duplicate-probe-process",
                duplicate_process,
                "BINARY_PERFORMANCE_RECORDED_PROCESS_ISOLATION_INVALID",
                "recorded_probe_process_ids",
            ),
            (
                "inconsistent-authority-binding",
                inconsistent_binding,
                "BINARY_PERFORMANCE_RECORDED_PROBE_INVALID",
                "pipeline_performance_authority_binding.consistency",
            ),
        )
        for label, mutate, reason_code, field in mutations:
            with self.subTest(label=label):
                rejected(label, mutate, reason_code, field)

    def test_recorded_gate_stage_timing_and_warm_alignment_matrix(self):
        base = self.recorded_gate_fixture()
        implementation = base["measurement_protocol"]["implementation"]

        def rejected(label, mutate, reason_code, field=None):
            evidence = deepcopy(base)
            mutate(evidence)
            result = gate._evaluate_recorded_gate(
                evidence, current_source_implementation=implementation,
            )
            self.assertEqual(result["status"], "failed", label)
            matching = [
                issue for issue in result["issues"]
                if issue["reason_code"] == reason_code
                and (field is None or issue.get("field") == field)
            ]
            self.assertTrue(matching, (label, result["issues"]))

        def append_extra_stage_sample(value):
            recorded = value["recorded_measurements"]
            recorded["warm_end_to_end_samples_seconds"] = (
                recorded["warm_end_to_end_samples_seconds"][:1]
            )
            recorded["warm_stage_seconds_samples"] = (
                recorded["warm_stage_seconds_samples"][:2]
            )

        mutations = (
            (
                "aggregate-stage-invalid-number",
                lambda value: value["recorded_measurements"]["stage_seconds"].__setitem__(
                    "report_10000_p95", -1,
                ),
                "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "stage_seconds",
            ),
            (
                "cold-stage-invalid-number",
                lambda value: value["recorded_measurements"][
                    "cold_stage_seconds"
                ].__setitem__("report_10000", -1),
                "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "cold_stage_seconds",
            ),
            (
                "cold-stage-nonfinite-wall",
                lambda value: value["recorded_measurements"].__setitem__(
                    "cold_end_to_end_seconds", math.inf,
                ),
                "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "cold_stage_seconds.total",
            ),
            (
                "warm-stage-nonmapping",
                lambda value: value["recorded_measurements"][
                    "warm_stage_seconds_samples"
                ].__setitem__(0, []),
                "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "warm_stage_seconds_samples[0]",
            ),
            (
                "warm-stage-wrong-keys",
                lambda value: value["recorded_measurements"][
                    "warm_stage_seconds_samples"
                ].__setitem__(0, {}),
                "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "warm_stage_seconds_samples[0]",
            ),
            (
                "warm-stage-invalid-number",
                lambda value: value["recorded_measurements"][
                    "warm_stage_seconds_samples"
                ][0].__setitem__("report_10000", -1),
                "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "warm_stage_seconds_samples[0]",
            ),
            (
                "warm-stage-nonfinite-wall",
                lambda value: value["recorded_measurements"][
                    "warm_end_to_end_samples_seconds"
                ].__setitem__(0, math.inf),
                "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "warm_stage_seconds_samples[0].total",
            ),
            (
                "warm-stage-sample-without-wall",
                append_extra_stage_sample,
                "BINARY_PERFORMANCE_RECORDED_STAGE_INVALID",
                "warm_stage_seconds_samples[1].total",
            ),
            (
                "warm-run-missing-parallel-arrays",
                lambda value: value["recorded_measurements"].update({
                    "warm_cpu_seconds_samples": [],
                    "warm_average_cpu_cores_samples": [],
                    "warm_parser_invocations_samples": [],
                    "warm_cache_hits_samples": [],
                    "warm_peak_rss_bytes_samples": [],
                    "warm_stage_seconds_samples": [],
                }),
                "BINARY_PERFORMANCE_RECORDED_CPU_INVALID",
                "warm[0]",
            ),
            (
                "authority-block-flag",
                lambda value: value.__setitem__(
                    "blocks_binary_authority_switch", True,
                ),
                "BINARY_PERFORMANCE_RECORDED_AUTHORITY_STATE_INVALID",
                None,
            ),
        )
        for label, mutate, reason_code, field in mutations:
            with self.subTest(label=label):
                rejected(label, mutate, reason_code, field)

    def test_source_owned_recorded_builder_failure_boundary_matrix(self):
        with self.assertRaisesRegex(
            gate.PerformanceGateError, "cannot consume another provisional",
        ):
            gate.build_recorded_gate_from_result(
                b"{}", captured_at="2026-08-20T00:00:00Z",
                provisional=True, provisional_gate_content=b"{}",
            )

        policy = gate.release_policy()
        implementation = self.implementation()

        def raw_result():
            protocol = deepcopy(policy["measurement_protocol"])
            protocol.update({
                "implementation": deepcopy(implementation),
                "source_implementation_identity": implementation[
                    "source_implementation_identity"
                ],
                "runtime_implementation_identity": implementation[
                    "runtime_implementation_identity"
                ],
            })
            binding = {"evidence_sha256": "0" * 64}
            return {
                "measurement_protocol": protocol,
                "measurements": {
                    "full_pipeline_probe": {
                        "pipeline_performance_authority_binding": dict(binding),
                    },
                    "changed_full_pipeline_probe": {
                        "pipeline_performance_authority_binding": dict(binding),
                    },
                },
            }

        def invoke(
            *, raw=None, provisional=True, provisional_evidence=None,
            provisional_verification=None, built_verification=None,
            live_implementation=None,
        ):
            raw = raw or raw_result()
            provisional_evidence = provisional_evidence or {
                "recorded_measurements": {
                    "captured_at": "2026-08-19T00:00:00Z",
                },
                "measurement_protocol": {
                    "implementation": deepcopy(implementation),
                },
            }
            parsed = [raw]
            provisional_content = None
            if not provisional:
                parsed.append(provisional_evidence)
                provisional_content = b"provisional"
            provisional_results = []
            if not provisional:
                provisional_results.append(
                    provisional_verification
                    or {"status": "passed", "issues": []}
                )
            if provisional:
                provisional_results.append(
                    built_verification or {"status": "passed", "issues": []}
                )
            with patch.object(
                gate, "_json_object_from_exact_bytes", side_effect=parsed,
            ), patch.object(
                gate, "_validate_raw_release_result", return_value=raw,
            ), patch.object(
                gate, "release_policy", return_value=policy,
            ), patch.object(
                gate, "resolve_asm_jar", return_value=Path("/asm.jar"),
            ), patch.object(
                gate, "_performance_implementation_protocol",
                return_value=live_implementation or implementation,
            ), patch.object(
                gate, "_recorded_measurements_from_result", return_value={},
            ), patch.object(
                gate, "evaluate_provisional_gate",
                side_effect=provisional_results,
            ), patch.object(
                gate, "evaluate_recorded_gate",
                return_value=built_verification
                or {"status": "passed", "issues": []},
            ):
                return gate.build_recorded_gate_from_result(
                    b"raw",
                    captured_at="2026-08-20T00:00:00Z",
                    provisional=provisional,
                    provisional_gate_content=provisional_content,
                )

        mismatched_raw = raw_result()
        mismatched_raw["measurement_protocol"]["implementation"] = {
            "different": True,
        }
        with self.assertRaisesRegex(
            gate.PerformanceGateError, "not the live builder implementation",
        ):
            invoke(raw=mismatched_raw)

        for issues in ([], [{"reason_code": "PROVISIONAL_REJECTED"}]):
            with self.subTest(provisional_issues=issues), self.assertRaises(
                gate.PerformanceGateError,
            ) as raised:
                invoke(
                    provisional=False,
                    provisional_verification={
                        "status": "failed", "issues": issues,
                    },
                )
            self.assertEqual(
                raised.exception.failure["reason_code"],
                "BINARY_PERFORMANCE_PROVISIONAL_EVIDENCE_INVALID",
            )
            self.assertEqual(raised.exception.failure["issues"], issues)

        for label, provisional_evidence, message in (
            (
                "nonmapping-measurements",
                {
                    "recorded_measurements": [],
                    "measurement_protocol": {
                        "implementation": deepcopy(implementation),
                    },
                },
                "later than provisional",
            ),
            (
                "empty-measurements",
                {
                    "recorded_measurements": {},
                    "measurement_protocol": {
                        "implementation": deepcopy(implementation),
                    },
                },
                "later than provisional",
            ),
            (
                "missing-provisional-protocol",
                {
                    "recorded_measurements": {
                        "captured_at": "2026-08-19T00:00:00Z",
                    },
                    "measurement_protocol": {},
                },
                "does not use the provisional implementation",
            ),
            (
                "implementation-mismatch",
                {
                    "recorded_measurements": {
                        "captured_at": "2026-08-19T00:00:00Z",
                    },
                    "measurement_protocol": {
                        "implementation": {"different": True},
                    },
                },
                "does not use the provisional implementation",
            ),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                gate.PerformanceGateError, message,
            ):
                invoke(
                    provisional=False,
                    provisional_evidence=provisional_evidence,
                )

        for issues in ([], [{"reason_code": "SELF_REPLAY_REJECTED"}]):
            with self.subTest(built_issues=issues), self.assertRaises(
                gate.PerformanceGateError,
            ) as raised:
                invoke(
                    built_verification={"status": "failed", "issues": issues},
                )
            self.assertEqual(
                raised.exception.failure["reason_code"],
                "BINARY_PERFORMANCE_BUILT_EVIDENCE_INVALID",
            )
            self.assertEqual(raised.exception.failure["issues"], issues)

    def test_benchmark_release_and_measurement_failure_boundary_matrix(self):
        implementation = self.implementation()
        changed_implementation = deepcopy(implementation)
        changed_implementation["source_implementation_identity"] = "f" * 64
        reference_runtime = {
            "machine_identity": "machine",
            "machine": {"logical_cpu_count": 8},
            "tool_versions": {},
            "cpu_time_source": "test-cpu",
            "peak_rss_source": "test-rss",
            "jdk_preflight_identity": implementation["jdk_preflight_identity"],
        }
        artifacts = [{"sha256": "a" * 64}]
        changed_artifacts = [{"sha256": "b" * 64}]

        def analysis_run(*, parser=0, classes=1, wall=1.0, cpu=0.5):
            value = self.valid_analysis_run()
            value.update({
                "end_to_end_seconds": wall,
                "cpu_seconds": cpu,
                "average_cpu_cores": cpu / wall if wall else 0.0,
                "parser_invocations": parser,
            })
            value["counts"]["classes"] = classes
            return value

        def probe(*, changed=False, jar_count=1, classes=1, wall=1.0, cpu=0.5):
            value = self.valid_raw_probe()
            value.update({
                "jar_count": jar_count,
                "current_jar_count": jar_count,
                "expected_class_count": classes,
                "class_count": classes,
                "base_class_count": classes,
                "current_class_count": classes,
                "comparison": "changed" if changed else "identical",
                "end_to_end_seconds": wall,
                "cpu_seconds": cpu,
                "average_cpu_cores": cpu / wall if wall else 0.0,
            })
            return value

        def invoke(
            *, release=False, runtime_mismatch=False,
            implementation_mismatch=False, dataset_mismatch=False,
            warm_parsers=None, cold_classes=None,
            implementation_changes=False, legacy_wall=2.0,
            zero_wall=False,
        ):
            jar_count = 400 if release else 1
            classes_per_jar = 250 if release else 1
            warm_samples = 3 if release else max(1, len(warm_parsers or []))
            include_legacy = release or legacy_wall is not None
            expected_classes = jar_count * classes_per_jar
            warm_parsers = list(warm_parsers or [0] * warm_samples)
            run_wall = 0.0 if zero_wall else 1.0
            run_cpu = 0.0 if zero_wall else 0.5
            warmup = analysis_run(
                parser=jar_count, classes=expected_classes,
                wall=run_wall, cpu=run_cpu,
            )
            cold = analysis_run(
                parser=jar_count,
                classes=(
                    cold_classes
                    if cold_classes is not None else expected_classes
                ),
                wall=run_wall, cpu=run_cpu,
            )
            warm_runs = [
                analysis_run(
                    parser=parser_count,
                    classes=expected_classes,
                    wall=run_wall,
                    cpu=run_cpu,
                )
                for parser_count in warm_parsers
            ]
            legacy = {
                "end_to_end_seconds": (
                    0.0 if zero_wall else float(legacy_wall or 0.0)
                ),
                "cpu_seconds": run_cpu,
                "average_cpu_cores": 0.0,
                "class_count": expected_classes,
                "peak_rss_bytes": 100,
                "implementation": "legacy",
            }
            full_probe = probe(
                jar_count=jar_count, classes=expected_classes,
                wall=run_wall, cpu=run_cpu,
            )
            changed_probe = probe(
                changed=True, jar_count=jar_count, classes=expected_classes,
                wall=run_wall, cpu=run_cpu,
            )
            policy = deepcopy(gate.release_policy())
            policy["reference_runtime"] = deepcopy(reference_runtime)
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
            if implementation_mismatch:
                policy["reference_implementation"][
                    "validator_implementation_identity"
                ] = "0" * 64
            policy["measurement_protocol"].update({
                "dataset_identity": (
                    "0" * 64 if dataset_mismatch else "d" * 64
                ),
                "first_base_artifact_identity": "a" * 64,
            })
            policy["measurement_protocol"]["changed_full_pipeline_probe"].update({
                "current_artifact_identity": "b" * 64,
                "logical_artifact_derivation_identity": "e" * 64,
            })
            observed_runtime = deepcopy(reference_runtime)
            if runtime_mismatch:
                observed_runtime["machine_identity"] = "different"
            implementation_results = (
                [implementation, changed_implementation]
                if implementation_changes else implementation
            )
            with tempfile.TemporaryDirectory() as temporary, patch.object(
                gate, "resolve_asm_jar", return_value=Path("/asm.jar"),
            ), patch.object(
                gate, "_performance_implementation_protocol",
                side_effect=implementation_results
                if isinstance(implementation_results, list) else None,
                return_value=(
                    None if isinstance(implementation_results, list)
                    else implementation_results
                ),
            ), patch.object(
                gate, "_reference_runtime_protocol", return_value=observed_runtime,
            ), patch.object(
                gate, "release_policy", return_value=policy,
            ), patch.object(
                gate, "build_dataset", return_value=artifacts,
            ), patch.object(
                gate, "build_changed_current_artifacts",
                return_value=changed_artifacts,
            ), patch.object(
                gate, "_dataset_identity", return_value="d" * 64,
            ), patch.object(
                gate, "_changed_artifact_derivation_identity",
                return_value="e" * 64,
            ), patch.object(
                gate, "_analyze_once",
                side_effect=[warmup, cold, *warm_runs],
            ), patch.object(
                gate, "_legacy_javap", return_value=legacy,
            ), patch.object(
                gate, "_run_isolated_full_pipeline_probe",
                side_effect=[full_probe, changed_probe],
            ):
                return gate.run_benchmark(
                    Path(temporary),
                    jar_count=jar_count,
                    classes_per_jar=classes_per_jar,
                    warm_samples=warm_samples,
                    include_legacy=include_legacy,
                )

        successful_release = invoke(release=True)
        self.assertEqual(
            successful_release["measurement_protocol"]["class_count"], 100_000,
        )

        for label, kwargs, message in (
            (
                "runtime-mismatch", {"release": True, "runtime_mismatch": True},
                "reference runtime",
            ),
            (
                "implementation-pin-mismatch",
                {"release": True, "implementation_mismatch": True},
                "implementation does not match",
            ),
            (
                "dataset-mismatch", {"release": True, "dataset_mismatch": True},
                "release dataset",
            ),
            (
                "warm-parser-after-valid",
                {"warm_parsers": [0, 1], "legacy_wall": None},
                "parser invocation",
            ),
            (
                "class-conservation",
                {"cold_classes": 0, "legacy_wall": None},
                "class conservation",
            ),
            (
                "implementation-changed",
                {"implementation_changes": True, "legacy_wall": None},
                "changed during benchmark",
            ),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                gate.PerformanceGateError, message,
            ):
                invoke(**kwargs)

        no_legacy_ratio = invoke(legacy_wall=0.0)
        self.assertIsNone(
            no_legacy_ratio["measurements"]["cold_relative_legacy_ratio"],
        )
        zero_total = invoke(legacy_wall=None, zero_wall=True)
        self.assertEqual(zero_total["measurements"]["average_cpu_cores"], 0.0)

        for issues in ([], [{"reason_code": "PROVISIONAL_REJECTED"}]):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                provisional_path = root / "provisional.json"
                provisional_path.write_bytes(b"{}")
                with patch.object(
                    gate, "resolve_asm_jar", return_value=Path("/asm.jar"),
                ), patch.object(
                    gate, "_performance_implementation_protocol",
                    return_value=implementation,
                ), patch.object(
                    gate, "_json_object_from_exact_bytes", return_value={},
                ), patch.object(
                    gate, "evaluate_provisional_gate",
                    return_value={"status": "failed", "issues": issues},
                ), self.assertRaises(gate.PerformanceGateError) as raised:
                    gate.run_benchmark(
                        root / "work", jar_count=1, classes_per_jar=1,
                        warm_samples=1, include_legacy=False,
                        provisional_gate_path=provisional_path,
                    )
            self.assertEqual(
                raised.exception.failure["issues"], issues,
            )

    def test_performance_cli_argument_and_result_boundary_matrix(self):
        def run_cli(argv):
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stderr(stderr), redirect_stdout(stdout):
                try:
                    code = gate.main(argv)
                except SystemExit as error:
                    code = int(error.code or 0)
            return code, stdout.getvalue(), stderr.getvalue()

        for label, argv in (
            ("worker-input-only", ["--probe-worker-input", "input.json"]),
            ("worker-output-only", ["--probe-worker-output", "output.json"]),
            (
                "builder-output-missing",
                ["--build-provisional-from-result", "raw.json"],
            ),
            (
                "builder-capture-missing",
                [
                    "--build-provisional-from-result", "raw.json",
                    "--output", "output.json",
                ],
            ),
            (
                "final-provisional-missing",
                [
                    "--build-final-from-result", "raw.json",
                    "--captured-at", "2026-08-20T00:00:00Z",
                    "--output", "output.json",
                ],
            ),
            (
                "candidate-provisional-forbidden",
                [
                    "--build-provisional-from-result", "raw.json",
                    "--provisional-gate", "provisional.json",
                    "--captured-at", "2026-08-20T00:00:00Z",
                    "--output", "output.json",
                ],
            ),
            ("benchmark-output-missing", []),
            (
                "jar-count-zero",
                ["--output", "result.json", "--jar-count", "0"],
            ),
            (
                "classes-per-jar-zero",
                ["--output", "result.json", "--classes-per-jar", "0"],
            ),
            (
                "warm-samples-zero",
                ["--output", "result.json", "--warm-samples", "0"],
            ),
            (
                "nondedicated-work-root",
                ["--output", "result.json", "--work-root", "."],
            ),
        ):
            with self.subTest(label=label):
                code, _stdout, _stderr = run_cli(argv)
                self.assertEqual(code, 2)

        with patch.object(
            gate, "_distinct_cli_output_path", return_value=Path("/output.json"),
        ), patch.object(gate, "_run_probe_worker", return_value=7) as worker:
            code, _stdout, _stderr = run_cli([
                "--probe-worker-input", "input.json",
                "--probe-worker-output", "output.json",
            ])
        self.assertEqual(code, 7)
        worker.assert_called_once_with(
            Path("input.json").resolve(), Path("/output.json"),
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw_path = root / "raw.json"
            provisional_path = root / "provisional.json"
            raw_path.write_bytes(b"{}")
            provisional_path.write_bytes(b"{}")
            for provisional_build in (True, False):
                output_path = root / (
                    "candidate.json" if provisional_build else "final.json"
                )
                argv = [
                    (
                        "--build-provisional-from-result"
                        if provisional_build else "--build-final-from-result"
                    ),
                    str(raw_path),
                    "--captured-at", "2026-08-20T00:00:00Z",
                    "--output", str(output_path),
                ]
                if not provisional_build:
                    argv.extend(["--provisional-gate", str(provisional_path)])
                with self.subTest(provisional=provisional_build), patch.object(
                    gate, "build_recorded_gate_from_result",
                    return_value={"status": "passed"},
                ) as builder:
                    code, stdout, _stderr = run_cli(argv)
                self.assertEqual(code, 0)
                self.assertEqual(
                    gate.json.loads(stdout)["evidence_kind"],
                    "provisional" if provisional_build else "final",
                )
                self.assertEqual(
                    builder.call_args.kwargs["provisional"], provisional_build,
                )

            class NonMappingFailure(RuntimeError):
                failure = []

            structured_failure = gate.PerformanceGateError(
                "structured",
                failure={
                    "reason_code": "STRUCTURED_BUILD_FAILURE",
                    "issues": [
                        1,
                        {"unserializable": object()},
                        {"reason_code": "PRESERVED_ISSUE"},
                    ],
                },
            )
            for label, error, expected_issue in (
                (
                    "nonmapping-failure",
                    NonMappingFailure("nonmapping"),
                    "BINARY_PERFORMANCE_EVIDENCE_BUILD_FAILED",
                ),
                (
                    "mixed-structured-issues",
                    structured_failure,
                    "PRESERVED_ISSUE",
                ),
            ):
                output_path = root / f"failure-{label}.json"
                with self.subTest(label=label), patch.object(
                    gate, "build_recorded_gate_from_result", side_effect=error,
                ):
                    code, _stdout, _stderr = run_cli([
                        "--build-provisional-from-result", str(raw_path),
                        "--captured-at", "2026-08-20T00:00:00Z",
                        "--output", str(output_path),
                    ])
                self.assertEqual(code, 1)
                failure = gate.json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(failure["issues"][0]["reason_code"], expected_issue)

            verification_path = root / "recorded.json"
            verification_path.write_bytes(b"{}")
            verification_output = root / "verification.json"
            for status, use_output, expected in (
                ("passed", True, 0),
                ("failed", False, 1),
            ):
                verification = {
                    "status": status,
                    "issue_count": int(status == "failed"),
                    "issues": [],
                }
                argv = ["--verify-recorded-gate", str(verification_path)]
                if use_output:
                    argv.extend(["--output", str(verification_output)])
                with self.subTest(verification=status), patch.object(
                    gate, "evaluate_recorded_gate", return_value=verification,
                ):
                    code, _stdout, _stderr = run_cli(argv)
                self.assertEqual(code, expected)
                if use_output:
                    self.assertEqual(
                        gate.json.loads(
                            verification_output.read_text(encoding="utf-8")
                        ),
                        verification,
                    )

            result = self.valid_raw_release_result()
            result["measurement_protocol"]["dataset_identity"] = "d" * 64
            result["measurements"]["legacy"] = None
            output_path = root / "benchmark.json"
            work_root = root / "benchmark-work"
            with patch.object(gate, "run_benchmark", return_value=result) as benchmark:
                code, stdout, _stderr = run_cli([
                    "--output", str(output_path),
                    "--work-root", str(work_root),
                    "--provisional-gate", str(provisional_path),
                    "--skip-legacy",
                ])
            self.assertEqual(code, 0)
            self.assertIsNone(gate.json.loads(stdout)["legacy_seconds"])
            self.assertEqual(
                benchmark.call_args.kwargs["provisional_gate_path"],
                provisional_path.resolve(),
            )

            benchmark_gate = root / "gate.json"
            benchmark_gate.write_bytes(b"{}")
            failed_evaluation = {"status": "failed", "issues": [{}]}
            with patch.object(
                gate, "run_benchmark", return_value=deepcopy(result),
            ), patch.object(
                gate, "evaluate_gate", return_value=failed_evaluation,
            ):
                code, _stdout, _stderr = run_cli([
                    "--output", str(root / "gated-result.json"),
                    "--work-root", str(root / "gated-work"),
                    "--gate", str(benchmark_gate),
                ])
            self.assertEqual(code, 1)

            nonmapping_performance_failure = gate.PerformanceGateError(
                "nonmapping structured failure",
            )
            nonmapping_performance_failure.failure = []
            for label, error in (
                ("plain", RuntimeError("plain failure")),
                ("nonmapping-structured", nonmapping_performance_failure),
                ("empty-structured", gate.PerformanceGateError("empty")),
                (
                    "structured",
                    gate.PerformanceGateError(
                        "structured",
                        failure={"reason_code": "BENCHMARK_REJECTED"},
                    ),
                ),
            ):
                with self.subTest(benchmark_failure=label), patch.object(
                    gate, "run_benchmark", side_effect=error,
                ):
                    code, _stdout, _stderr = run_cli([
                        "--output", str(root / f"benchmark-failure-{label}.json"),
                        "--work-root", str(root / f"failure-work-{label}"),
                    ])
                self.assertEqual(code, 1)

    def test_provisional_marker_and_live_resolution_matrix(self):
        implementation = self.implementation()
        protocol = {
            "implementation": implementation,
            "source_implementation_identity": implementation[
                "source_implementation_identity"
            ],
            "runtime_implementation_identity": implementation[
                "runtime_implementation_identity"
            ],
            "dataset_identity": "d" * 64,
        }
        marker = {
            "schema": "java-upgrade-analyzer.binary-performance-provisional.v1",
            "purpose": "isolated_release_path_recapture_only",
            "source_implementation_identity": protocol[
                "source_implementation_identity"
            ],
            "runtime_implementation_identity": protocol[
                "runtime_implementation_identity"
            ],
            "dataset_identity": protocol["dataset_identity"],
            "candidate_probe_authority_mode": (
                gate._CANDIDATE_PROBE_AUTHORITY_MODE
            ),
            "candidate_result_sha256": "e" * 64,
            "public_activation_allowed": False,
        }
        provisional = {
            "measurement_protocol": protocol,
            "measurement_provisional": marker,
        }
        verified = {"status": "passed", "issues": []}
        with patch.object(
            gate, "evaluate_recorded_gate", return_value=verified,
        ) as replay:
            result = gate.evaluate_provisional_gate(
                provisional,
                _current_source_implementation=implementation,
            )
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["provisional_recapture_only"])
        replay.assert_called_once()
        self.assertNotIn(
            "measurement_provisional", replay.call_args.args[0],
        )

        self.assertEqual(
            gate.evaluate_provisional_gate([])["issues"][0]["reason_code"],
            "BINARY_PERFORMANCE_PROVISIONAL_ROOT_INVALID",
        )
        invalid_cases = []
        invalid_cases.append(("protocol-shape", {
            "measurement_protocol": [],
            "measurement_provisional": marker,
        }))
        invalid_cases.append(("marker-shape", {
            "measurement_protocol": protocol,
            "measurement_provisional": [],
        }))
        marker_mismatch = deepcopy(provisional)
        marker_mismatch["measurement_provisional"]["purpose"] = "wrong"
        invalid_cases.append(("marker-value", marker_mismatch))
        implementation_shape = deepcopy(provisional)
        implementation_shape["measurement_protocol"]["implementation"] = []
        invalid_cases.append(("implementation-shape", implementation_shape))
        for field in (
            "source_implementation_identity",
            "runtime_implementation_identity",
            "dataset_identity",
        ):
            item = deepcopy(provisional)
            item["measurement_protocol"][field] = "bad"
            item["measurement_provisional"][field] = "bad"
            invalid_cases.append((field, item))
        candidate_sha = deepcopy(provisional)
        candidate_sha["measurement_provisional"][
            "candidate_result_sha256"
        ] = "bad"
        invalid_cases.append(("candidate-sha", candidate_sha))
        for label, value in invalid_cases:
            with self.subTest(label=label):
                result = gate.evaluate_provisional_gate(
                    value,
                    _current_source_implementation=implementation,
                )
                self.assertEqual(
                    result["issues"][0]["reason_code"],
                    "BINARY_PERFORMANCE_PROVISIONAL_MARKER_INVALID",
                )

        with patch.object(
            gate, "resolve_asm_jar", return_value=Path("/asm.jar"),
        ), patch.object(
            gate, "_performance_implementation_protocol",
            return_value=implementation,
        ), patch.object(
            gate, "evaluate_recorded_gate", return_value=verified,
        ):
            self.assertEqual(
                gate.evaluate_provisional_gate(provisional)["status"], "passed",
            )
        with patch.object(
            gate, "resolve_asm_jar", side_effect=RuntimeError("unavailable"),
        ):
            unavailable = gate.evaluate_provisional_gate(provisional)
        self.assertEqual(
            unavailable["issues"][0]["reason_code"],
            "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_UNAVAILABLE",
        )


if __name__ == "__main__":
    unittest.main()
