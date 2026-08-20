import copy
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_asm_helper  # noqa: E402
import binary_output  # noqa: E402
import binary_performance_gate  # noqa: E402
import binary_pipeline  # noqa: E402
from binary_first_contract import canonical_identity  # noqa: E402
from tests import test_binary_output as binary_output_fixtures  # noqa: E402
from tests import (  # noqa: E402
    test_binary_performance_gate as performance_gate_fixtures,
)


_AUTHORITY_SIDECAR = "binary_publication_authority.json"
_PROBE_NAMES = ("full_pipeline_probe", "changed_full_pipeline_probe")


def _binding(*, mode="release_evidence", variant="1"):
    value = {
        "schema": "java-upgrade-analyzer.performance-authority-binding.v2",
        "authority_mode": mode,
        "support_contract_identity": variant * 64,
        "evidence_sha256": str((int(variant) + 1) % 10) * 64,
        "source_implementation_identity": str((int(variant) + 2) % 10) * 64,
    }
    value["binding_identity"] = canonical_identity(
        "binary_performance_authority_binding_identity",
        {
            "support_contract_identity": value["support_contract_identity"],
            "evidence_sha256": value["evidence_sha256"],
            "source_implementation_identity": value[
                "source_implementation_identity"
            ],
            "authority_mode": value["authority_mode"],
        },
        schema_version="1",
    )
    return value


def _refresh_binding_identity(value):
    value["binding_identity"] = canonical_identity(
        "binary_performance_authority_binding_identity",
        {
            "support_contract_identity": value[
                "support_contract_identity"
            ],
            "evidence_sha256": value["evidence_sha256"],
            "source_implementation_identity": value[
                "source_implementation_identity"
            ],
            "authority_mode": value["authority_mode"],
        },
        schema_version="1",
    )
    return value


def _authority_sidecar(binding):
    value = {
        "schema": "java-upgrade-analyzer.binary-publication-authority.v1",
        "authority_mode": binding["authority_mode"],
        "binding_identity": binding["binding_identity"],
        "public_activation_allowed": (
            binding["authority_mode"] == "release_evidence"
        ),
        "performance_authority_gate_binding": dict(binding),
    }
    return binary_output._json_bytes(value)


def _worker_implementation():
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
    return implementation


def _worker_artifact(root):
    path = Path(root) / "artifact-0000.jar"
    path.write_bytes(b"probe-boundary-fixture")
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "byte_length": path.stat().st_size,
        "jar_index": 0,
        "first_class_index": 0,
        "class_count": 1,
    }


def _worker_changed_artifact(root):
    path = Path(root) / "artifact-0000-changed.jar"
    path.write_bytes(b"changed-probe-boundary-fixture")
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "byte_length": path.stat().st_size,
        "jar_index": 0,
        "first_class_index": 0,
        "class_count": 1,
    }


def _worker_probe_result(implementation):
    mode = binary_performance_gate._CANDIDATE_PROBE_AUTHORITY_MODE
    binding = {
        "schema": (
            "java-upgrade-analyzer.performance-authority-binding.v2"
        ),
        "authority_mode": mode,
        "support_contract_identity": "8" * 64,
        "evidence_sha256": "9" * 64,
        "source_implementation_identity": implementation[
            "source_implementation_identity"
        ],
    }
    binding["binding_identity"] = canonical_identity(
        "binary_performance_authority_binding_identity",
        {
            "support_contract_identity": binding[
                "support_contract_identity"
            ],
            "evidence_sha256": binding["evidence_sha256"],
            "source_implementation_identity": binding[
                "source_implementation_identity"
            ],
            "authority_mode": mode,
        },
        schema_version="1",
    )
    phases = binary_performance_gate.FULL_PIPELINE_PHASES
    return {
        "status": "passed",
        "performance_authority_mode": mode,
        "comparison": "identical-base-current-cold-output",
        "process_id": os.getpid() + 100_000,
        "rss_measurement_scope": (
            "dedicated_probe_process_and_completed_children"
        ),
        "jar_count": 1,
        "current_jar_count": 1,
        "expected_class_count": 1,
        "end_to_end_seconds": 0.2,
        "pipeline_reported_seconds": 0.1,
        "pipeline_total_elapsed_scope": "current_pipeline_attempt",
        "pipeline_phase_timings_scope": "current_pipeline_attempt",
        "cpu_seconds": 0.1,
        "average_cpu_cores": 0.5,
        "phase_seconds": {name: 0.01 for name in phases},
        "phase_peak_rss_bytes": {name: 1 for name in phases},
        "pipeline_reported_peak_rss_bytes": 1,
        "post_pipeline_peak_rss_bytes": 1,
        "peak_rss_bytes": 1,
        "pipeline_performance_authority_binding": binding,
        "activation_authority_mode": mode,
        "publication_deferred": False,
        "checkpoint_retained": False,
        "activation_candidate_discarded": True,
        "activation_recapture_discarded": False,
        "active_generation_absent": True,
        "pending_generation_absent": True,
        "validation_checkpoint_absent": True,
        "parser_invocations": 1,
        "artifact_snapshot_hits": 0,
        "artifact_snapshot_disk_hits": 0,
        "artifact_snapshot_memory_hits": 0,
        "class_count": 1,
        "base_class_count": 1,
        "current_class_count": 1,
        "validation_status": "passed",
        "validation_issue_count": 0,
        "authoritative_change_fact_count": 0,
        "authoritative_member_change_kind_counts": {},
        "formal_api_result_count": 0,
        "formal_reachability_status_counts": {},
        "formal_impact_conclusion_counts": {},
    }


def _raw_analysis_sample(*, warm=False):
    stages = {
        "inventory": 0.01,
        "parse_and_cache": 0.01 if warm else 0.10,
        "db_write_and_index": 0.01 if warm else 0.10,
        "overlay": 0.0,
        "batch_query_10000": 0.01,
        "report_10000": 0.01,
    }
    sqlite_bytes = 4_000_000
    cache_bytes = 1_000_000
    return {
        "end_to_end_seconds": 1.0,
        "cpu_seconds": 0.5,
        "average_cpu_cores": 0.5,
        "stage_seconds": stages,
        "parser_invocations": 0 if warm else 400,
        "cache_hits": 400 if warm else 0,
        "counts": {
            "entries": 100_000,
            "classes": 100_000,
            "members": 300_000,
            "edges": 400_000,
            "resources": 0,
        },
        "inventory": {
            "entry_count": 100_000,
            "uncompressed_bytes": 10_000_000,
        },
        "overlay_status": "not_provided",
        "report_bytes": 1_000,
        "db_bytes": sqlite_bytes,
        "cache_bytes": cache_bytes,
        "peak_rss_bytes": 100_000_000,
        "bytes_per_class": (
            (sqlite_bytes + cache_bytes) / 100_000
        ),
        "bytes_per_edge": sqlite_bytes / 400_000,
    }


def _candidate_raw_result(candidate_gate):
    warmup = _raw_analysis_sample()
    cold = _raw_analysis_sample()
    warm = [_raw_analysis_sample(warm=True) for _ in range(3)]
    legacy = {
        "end_to_end_seconds": 100.0,
        "cpu_seconds": 50.0,
        "average_cpu_cores": 0.5,
        "class_count": 100_000,
        "peak_rss_bytes": 100_000_000,
        "implementation": "legacy-javap-c-s-p-batched-per-artifact",
    }
    full = copy.deepcopy(
        candidate_gate["recorded_measurements"]["full_pipeline_probe"]
    )
    changed = copy.deepcopy(
        candidate_gate["recorded_measurements"][
            "changed_full_pipeline_probe"
        ]
    )
    full.pop("captured_at")
    changed.pop("captured_at")
    measured_runs = [cold, *warm, legacy, full, changed]
    total_wall = sum(item["end_to_end_seconds"] for item in measured_runs)
    total_cpu = sum(item["cpu_seconds"] for item in measured_runs)
    return {
        "schema": binary_performance_gate.SCHEMA,
        "status": "measured",
        "measurement_protocol": copy.deepcopy(
            candidate_gate["measurement_protocol"]
        ),
        "measurements": {
            "warmup": warmup,
            "cold": cold,
            "warm_runs": warm,
            "warm_end_to_end_p50_seconds": 1.0,
            "warm_end_to_end_p95_seconds": 1.0,
            "legacy": legacy,
            "full_pipeline_probe": full,
            "changed_full_pipeline_probe": changed,
            "cold_relative_legacy_ratio": 0.01,
            "peak_rss_bytes": max([
                warmup["peak_rss_bytes"],
                cold["peak_rss_bytes"],
                *[item["peak_rss_bytes"] for item in warm],
                legacy["peak_rss_bytes"],
                full["peak_rss_bytes"],
                changed["peak_rss_bytes"],
            ]),
            "disk_bytes": cold["db_bytes"] + cold["cache_bytes"],
            "total_measured_wall_seconds": total_wall,
            "total_measured_cpu_seconds": total_cpu,
            "average_cpu_cores": total_cpu / total_wall,
        },
    }


def _recapture_raw_result(candidate_raw, provisional_content):
    result = copy.deepcopy(candidate_raw)
    provisional_sha256 = hashlib.sha256(provisional_content).hexdigest()
    mode = binary_performance_gate._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE
    for probe_name in _PROBE_NAMES:
        probe = result["measurements"][probe_name]
        probe["performance_authority_mode"] = mode
        probe["activation_authority_mode"] = mode
        probe["activation_candidate_discarded"] = False
        probe["activation_recapture_discarded"] = True
        binding = probe["pipeline_performance_authority_binding"]
        binding["authority_mode"] = mode
        binding["evidence_sha256"] = provisional_sha256
        binding["binding_identity"] = canonical_identity(
            "binary_performance_authority_binding_identity",
            {
                "support_contract_identity": binding[
                    "support_contract_identity"
                ],
                "evidence_sha256": binding["evidence_sha256"],
                "source_implementation_identity": binding[
                    "source_implementation_identity"
                ],
                "authority_mode": binding["authority_mode"],
            },
            schema_version="1",
        )
    return result


@contextmanager
def _worker_candidate_authority(*_args, **_kwargs):
    yield binary_performance_gate._CANDIDATE_PROBE_AUTHORITY_MODE


class PublicationAuthorityBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.fixture = binary_output_fixtures.BinaryOutputTest(
            methodName="runTest"
        )

    def _write_authorized_generation(self, root, *, binding=None):
        binding = dict(binding or _binding())
        decisions, traces = self.fixture.bundles()
        manifest = binary_output.write_binary_generation(
            root,
            decisions,
            traces,
            self.fixture.profile(),
            policy_identities={"registry": "v1"},
            additional_sidecars={
                _AUTHORITY_SIDECAR: _authority_sidecar(binding),
            },
        )
        return manifest, self.fixture.validation_result(manifest), binding

    def test_self_minted_release_authority_cannot_activate_without_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, validation, _binding_value = (
                self._write_authorized_generation(tmp)
            )

            with self.assertRaises(binary_output.BinaryOutputError) as caught:
                binary_output.activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    publication_guard=None,
                )

            self.assertFalse(
                (Path(tmp) / "active_binary_generation.json").exists()
            )
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_ACTIVE_GENERATION_PUBLICATION_GUARD_REQUIRED",
        )

    def test_pipeline_generation_needs_validation_not_performance_authority(self):
        decisions, traces = self.fixture.bundles()
        pipeline_only_sidecars = (
            binary_pipeline._REQUIRED_PIPELINE_GENERATION_SIDECARS
            - binary_output._REQUIRED_CORE_GENERATION_SIDECARS
            - {_AUTHORITY_SIDECAR}
        )
        with tempfile.TemporaryDirectory() as tmp:
            manifest = binary_output.write_binary_generation(
                tmp,
                decisions,
                traces,
                self.fixture.profile(),
                policy_identities={"registry": "v1"},
                additional_sidecars={
                    name: b"pipeline-fingerprint\n"
                    for name in pipeline_only_sidecars
                },
            )
            validation = self.fixture.validation_result(manifest)

            active = binary_output.activate_binary_generation(
                tmp,
                manifest,
                validation_result=validation,
                publication_guard=None,
            )

            self.assertEqual(
                Path(active).resolve(),
                (Path(tmp) / "active_binary_generation.json").resolve(),
            )

    def test_exact_guard_binding_allows_activation_and_sealing(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, validation, binding = self._write_authorized_generation(
                tmp
            )
            activation_record = {}

            with patch.object(
                binary_output,
                "_live_reauthorization_binding_is_current",
                return_value=True,
            ):
                active_path = binary_output.activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    publication_guard=lambda: dict(binding),
                    activation_record=activation_record,
                )
                sealed = binary_output.seal_active_binary_generation(
                    tmp,
                    expected_current_identity=manifest[
                        "result_generation_identity"
                    ],
                    expected_activation_identity=activation_record[
                        "activation_identity"
                    ],
                    publication_guard=lambda: dict(binding),
                )
            active = binary_output.read_active_binary_generation(tmp)

        self.assertTrue(active_path)
        self.assertTrue(sealed)
        self.assertEqual(
            active["result_generation_identity"],
            manifest["result_generation_identity"],
        )

    def test_stale_exact_guard_binding_is_rejected_by_internal_live_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, validation, binding = self._write_authorized_generation(
                tmp
            )
            with patch.object(
                binary_output,
                "_live_reauthorization_binding_is_current",
                return_value=False,
            ), self.assertRaises(binary_output.BinaryOutputError) as caught:
                binary_output.activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    publication_guard=lambda: dict(binding),
                )

            self.assertFalse(
                (Path(tmp) / "active_binary_generation.json").exists()
            )
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_ACTIVE_GENERATION_PUBLICATION_GUARD_MISMATCH",
        )

    def test_seal_rechecks_live_authority_at_consumer_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, validation, binding = self._write_authorized_generation(
                tmp
            )
            activation = "a" * 64
            with patch.object(
                binary_output,
                "_live_reauthorization_binding_is_current",
                return_value=True,
            ):
                binary_output.activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                    publication_guard=lambda: dict(binding),
                )
            active_path = Path(tmp) / "active_binary_generation.json"
            receipt_bytes = active_path.read_bytes()

            with patch.object(
                binary_output,
                "_live_reauthorization_binding_is_current",
                return_value=False,
            ), self.assertRaises(binary_output.BinaryOutputError) as caught:
                binary_output.seal_active_binary_generation(
                    tmp,
                    expected_current_identity=manifest[
                        "result_generation_identity"
                    ],
                    expected_activation_identity=activation,
                    publication_guard=lambda: dict(binding),
                )

            self.assertEqual(active_path.read_bytes(), receipt_bytes)
            self.assertIn(
                "activation_identity",
                json.loads(active_path.read_text(encoding="utf-8")),
            )
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_ACTIVE_GENERATION_PUBLICATION_GUARD_MISMATCH",
        )

    def test_seal_rejects_generation_or_receipt_mutation_by_live_guard(self):
        for target_kind in ("sidecar", "validation", "descriptor"):
            with (
                self.subTest(target=target_kind),
                tempfile.TemporaryDirectory() as tmp,
            ):
                manifest, validation, binding = (
                    self._write_authorized_generation(tmp)
                )
                activation = hashlib.sha256(
                    f"seal-guard-{target_kind}".encode("utf-8")
                ).hexdigest()
                active_path = Path(tmp) / "active_binary_generation.json"
                with patch.object(
                    binary_output,
                    "_live_reauthorization_binding_is_current",
                    return_value=True,
                ), patch.object(
                    binary_output,
                    "_filesystem_supports_direct_seal_fast_path",
                    return_value=True,
                ):
                    binary_output.activate_binary_generation(
                        tmp,
                        manifest,
                        validation_result=validation,
                        activation_identity=activation,
                        publication_guard=lambda: dict(binding),
                    )
                    receipt_bytes = active_path.read_bytes()
                    if target_kind == "sidecar":
                        target = (
                            Path(manifest["generation_directory"])
                            / "binary_summary.json"
                        )
                    elif target_kind == "validation":
                        target = Path(validation["validation_result_path"])
                    else:
                        target = active_path

                    def mutating_guard():
                        target.write_bytes(
                            target.read_bytes() + b"tampered-by-live-guard"
                        )
                        return dict(binding)

                    with self.assertRaises(
                        binary_output.BinaryOutputError
                    ):
                        binary_output.seal_active_binary_generation(
                            tmp,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity=activation,
                            publication_guard=mutating_guard,
                        )

                if target_kind == "descriptor":
                    self.assertIn(
                        b"tampered-by-live-guard", active_path.read_bytes()
                    )
                else:
                    self.assertEqual(active_path.read_bytes(), receipt_bytes)
                    self.assertFalse(
                        binary_output._public_active_is_sealed(
                            json.loads(
                                active_path.read_text(encoding="utf-8")
                            )
                        )
                    )

    def test_deferred_publish_rejects_guard_mutation_before_commit(self):
        for target_kind in ("sidecar", "validation", "descriptor"):
            with (
                self.subTest(target=target_kind),
                tempfile.TemporaryDirectory() as tmp,
            ):
                manifest, validation, binding = (
                    self._write_authorized_generation(tmp)
                )
                activation = hashlib.sha256(
                    f"publish-guard-{target_kind}".encode("utf-8")
                ).hexdigest()
                pending_path = (
                    Path(tmp)
                    / binary_output._PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                )
                with patch.object(
                    binary_output,
                    "_live_reauthorization_binding_is_current",
                    return_value=True,
                ):
                    binary_output.activate_binary_generation(
                        tmp,
                        manifest,
                        validation_result=validation,
                        activation_identity=activation,
                        defer_publication=True,
                        publication_guard=lambda: dict(binding),
                    )
                    pending_bytes = pending_path.read_bytes()
                    if target_kind == "sidecar":
                        target = (
                            Path(manifest["generation_directory"])
                            / "binary_summary.json"
                        )
                    elif target_kind == "validation":
                        target = Path(validation["validation_result_path"])
                    else:
                        target = pending_path

                    def mutating_guard():
                        target.write_bytes(
                            target.read_bytes() + b"tampered-by-live-guard"
                        )
                        return dict(binding)

                    with self.assertRaises(
                        binary_output.BinaryOutputError
                    ):
                        binary_output.publish_pending_binary_generation(
                            tmp,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity=activation,
                            publication_guard=mutating_guard,
                        )

                self.assertFalse(
                    (Path(tmp) / "active_binary_generation.json").exists()
                )
                if target_kind == "descriptor":
                    self.assertIn(
                        b"tampered-by-live-guard", pending_path.read_bytes()
                    )
                else:
                    self.assertEqual(pending_path.read_bytes(), pending_bytes)

    def test_post_guard_stat_probe_device_mismatch_forces_full_rehash(self):
        decisions, traces = self.fixture.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = binary_output.write_binary_generation(
                tmp,
                decisions,
                traces,
                self.fixture.profile(),
                policy_identities={"registry": "probe-device-mismatch"},
            )
            validation = self.fixture.validation_result(manifest)
            activation = "9" * 64
            original_verify = (
                binary_output._verify_pending_generation_integrity
            )
            with patch.object(
                binary_output,
                "_filesystem_supports_direct_seal_fast_path",
                return_value=True,
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                wraps=original_verify,
            ) as verify:
                binary_output.activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )
                binary_output._discard_current_direct_seal_capability()
                actual_device = os.lstat(Path(tmp).resolve()).st_dev
                with patch.object(
                    binary_output,
                    "_prepare_post_guard_stat_recheck",
                    return_value=actual_device + 1,
                ):
                    self.assertTrue(
                        binary_output.seal_active_binary_generation(
                            tmp,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity=activation,
                            publication_guard=lambda: None,
                        )
                    )

            # Activation proves once.  The seal proves before the guard and
            # must hash a second time afterward because the proof's device is
            # not the exact filesystem device whose ctime behavior was probed.
            self.assertEqual(verify.call_count, 3)

    def test_activate_rejects_same_length_predecessor_mutation_by_guard(self):
        decisions, traces = self.fixture.bundles()
        for deferred in (False, True):
            with (
                self.subTest(deferred=deferred),
                tempfile.TemporaryDirectory() as tmp,
            ):
                predecessor = binary_output.write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    self.fixture.profile(),
                    policy_identities={"registry": "predecessor"},
                )
                predecessor_validation = self.fixture.validation_result(
                    predecessor
                )
                predecessor_activation = "a" * 64
                binary_output.activate_binary_generation(
                    tmp,
                    predecessor,
                    validation_result=predecessor_validation,
                    activation_identity=predecessor_activation,
                )
                self.assertTrue(
                    binary_output.seal_active_binary_generation(
                        tmp,
                        expected_current_identity=predecessor[
                            "result_generation_identity"
                        ],
                        expected_activation_identity=(
                            predecessor_activation
                        ),
                    )
                )

                binding = _binding()
                successor = binary_output.write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    self.fixture.profile(),
                    policy_identities={"registry": "successor"},
                    additional_sidecars={
                        _AUTHORITY_SIDECAR: _authority_sidecar(binding),
                    },
                )
                successor_validation = self.fixture.validation_result(
                    successor
                )
                successor_activation = (
                    "c" * 64 if deferred else "b" * 64
                )
                active_path = Path(tmp) / "active_binary_generation.json"
                original_bytes = active_path.read_bytes()
                original_stat = os.lstat(active_path)
                mutated = {}

                def mutating_guard():
                    value = json.loads(original_bytes.decode("utf-8"))
                    old_identity = value["result_generation_identity"]
                    replacement = (
                        ("f" if old_identity[0] != "f" else "e")
                        + old_identity[1:]
                    )
                    value["result_generation_identity"] = replacement
                    value["generation_directory"] = (
                        f"binary_generations/{replacement}"
                    )
                    content = binary_output._json_bytes(value)
                    self.assertEqual(len(content), len(original_bytes))
                    active_path.write_bytes(content)
                    os.utime(
                        active_path,
                        ns=(
                            original_stat.st_atime_ns,
                            original_stat.st_mtime_ns,
                        ),
                        follow_symlinks=False,
                    )
                    mutated["content"] = content
                    return dict(binding)

                with patch.object(
                    binary_output,
                    "_live_reauthorization_binding_is_current",
                    return_value=True,
                ), patch.object(
                    binary_output,
                    "_filesystem_supports_direct_seal_fast_path",
                    return_value=True,
                ), self.assertRaises(
                    binary_output.BinaryOutputError
                ) as caught:
                    binary_output.activate_binary_generation(
                        tmp,
                        successor,
                        validation_result=successor_validation,
                        activation_identity=successor_activation,
                        defer_publication=deferred,
                        publication_guard=mutating_guard,
                    )

                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
                )
                self.assertEqual(
                    active_path.read_bytes(), mutated["content"]
                )
                self.assertIsNone(
                    binary_output.read_pending_binary_generation(
                        tmp, missing_ok=True
                    )
                )

    def test_activate_rejects_generation_mutation_by_guard_immediately(self):
        for mode in ("direct", "deferred", "dry_run"):
            for target_kind in ("sidecar", "validation"):
                with (
                    self.subTest(mode=mode, target=target_kind),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    requested_binding = (
                        _binding(mode="candidate_source_measurement")
                        if mode == "dry_run" else None
                    )
                    manifest, validation, binding = (
                        self._write_authorized_generation(
                            tmp, binding=requested_binding
                        )
                    )
                    if target_kind == "sidecar":
                        target = (
                            Path(manifest["generation_directory"])
                            / "binary_summary.json"
                        )
                    else:
                        target = Path(validation["validation_result_path"])

                    def mutating_guard():
                        target.write_bytes(
                            target.read_bytes()
                            + b"tampered-during-activation-guard"
                        )
                        return dict(binding)

                    with patch.object(
                        binary_output,
                        "_live_reauthorization_binding_is_current",
                        return_value=True,
                    ), patch.object(
                        binary_output,
                        "_filesystem_supports_direct_seal_fast_path",
                        return_value=True,
                    ), self.assertRaises(binary_output.BinaryOutputError):
                        binary_output.activate_binary_generation(
                            tmp,
                            manifest,
                            validation_result=validation,
                            activation_identity="d" * 64,
                            defer_publication=(mode == "deferred"),
                            publication_dry_run=(mode == "dry_run"),
                            publication_guard=mutating_guard,
                        )

                    self.assertFalse(
                        (Path(tmp) / "active_binary_generation.json").exists()
                    )
                    self.assertIsNone(
                        binary_output.read_pending_binary_generation(
                            tmp, missing_ok=True
                        )
                    )

    def test_candidate_dry_run_without_stat_support_rehashes_and_succeeds(self):
        candidate_binding = _binding(
            mode="candidate_source_measurement"
        )
        with tempfile.TemporaryDirectory() as tmp:
            manifest, validation, binding = (
                self._write_authorized_generation(
                    tmp, binding=candidate_binding
                )
            )
            original_verify = (
                binary_output._verify_pending_generation_integrity
            )
            with patch.object(
                binary_output,
                "_prepare_post_guard_stat_recheck",
                return_value=None,
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                wraps=original_verify,
            ) as verify, patch.object(
                binary_output,
                "_live_reauthorization_binding_is_current",
                return_value=True,
            ):
                self.assertEqual(
                    binary_output.activate_binary_generation(
                        tmp,
                        manifest,
                        validation_result=validation,
                        activation_identity="e" * 64,
                        publication_dry_run=True,
                        publication_guard=lambda: dict(binding),
                    ),
                    "",
                )

            self.assertEqual(verify.call_count, 2)
            self.assertFalse(
                (Path(tmp) / "active_binary_generation.json").exists()
            )

    def test_exact_sidecar_modes_preserve_special_publication_boundaries(self):
        modes = (
            "release_evidence",
            "candidate_source_measurement",
            "release_recapture_measurement",
        )
        for index, mode in enumerate(modes, start=1):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                binding = _binding(mode=mode, variant=str(index))
                manifest, validation, _binding_value = (
                    self._write_authorized_generation(tmp, binding=binding)
                )
                activation_record = {}
                with patch.object(
                    binary_output,
                    "_live_reauthorization_binding_is_current",
                    return_value=True,
                ):
                    if mode == "candidate_source_measurement":
                        self.assertEqual(
                            binary_output.activate_binary_generation(
                                tmp,
                                manifest,
                                validation_result=validation,
                                activation_identity="a" * 64,
                                activation_record=activation_record,
                                defer_publication=True,
                                publication_guard=lambda: dict(binding),
                                publication_dry_run=True,
                            ),
                            "",
                        )
                        self.assertFalse(
                            (Path(tmp) / "active_binary_generation.json").exists()
                        )
                        self.assertIsNone(
                            binary_output.read_pending_binary_generation(
                                tmp, missing_ok=True
                            )
                        )
                    elif mode == "release_recapture_measurement":
                        with binary_output._release_recapture_publication(tmp):
                            binary_output.activate_binary_generation(
                                tmp,
                                manifest,
                                validation_result=validation,
                                activation_identity="a" * 64,
                                activation_record=activation_record,
                                publication_guard=lambda: dict(binding),
                            )
                            self.assertTrue(
                                binary_output.seal_active_binary_generation(
                                    tmp,
                                    expected_current_identity=manifest[
                                        "result_generation_identity"
                                    ],
                                    expected_activation_identity="a" * 64,
                                    publication_guard=lambda: dict(binding),
                                )
                            )
                    else:
                        binary_output.activate_binary_generation(
                            tmp,
                            manifest,
                            validation_result=validation,
                            activation_identity="a" * 64,
                            activation_record=activation_record,
                            publication_guard=lambda: dict(binding),
                        )
                        self.assertTrue(
                            binary_output.seal_active_binary_generation(
                                tmp,
                                expected_current_identity=manifest[
                                    "result_generation_identity"
                                ],
                                expected_activation_identity="a" * 64,
                                publication_guard=lambda: dict(binding),
                            )
                        )

                if mode != "release_evidence":
                    with self.assertRaises(binary_output.BinaryOutputError):
                        binary_output.activate_binary_generation(
                            tmp,
                            manifest,
                            validation_result=validation,
                            activation_identity="b" * 64,
                            publication_guard=lambda: dict(binding),
                        )

    def test_direct_candidate_and_deferred_content_proof_counts(self):
        cases = (
            ("direct", "release_evidence", 1),
            ("candidate", "candidate_source_measurement", 1),
            ("deferred", "release_evidence", 2),
        )
        for label, authority_mode, full_proofs in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                binding = _binding(mode=authority_mode, variant="1")
                manifest, validation, _ = self._write_authorized_generation(
                    tmp, binding=binding
                )
                activation = hashlib.sha256(label.encode("utf-8")).hexdigest()
                activation_record = {}
                real_sha256 = binary_output._sha256_file
                real_verify = (
                    binary_output._verify_pending_generation_integrity
                )
                with patch.object(
                    binary_output,
                    "_live_reauthorization_binding_is_current",
                    return_value=True,
                ), patch.object(
                    binary_output,
                    "_filesystem_supports_direct_seal_fast_path",
                    return_value=True,
                ), patch.object(
                    binary_output,
                    "_sha256_file",
                    wraps=real_sha256,
                ) as sha256_file, patch.object(
                    binary_output,
                    "_verify_pending_generation_integrity",
                    wraps=real_verify,
                ) as verify:
                    binary_output.activate_binary_generation(
                        tmp,
                        manifest,
                        validation_result=validation,
                        activation_identity=activation,
                        activation_record=activation_record,
                        defer_publication=(label != "direct"),
                        publication_guard=lambda: dict(binding),
                        publication_dry_run=(label == "candidate"),
                    )
                    if label == "direct":
                        self.assertTrue(
                            binary_output.seal_active_binary_generation(
                                tmp,
                                expected_current_identity=manifest[
                                    "result_generation_identity"
                                ],
                                expected_activation_identity=activation,
                                publication_guard=lambda: dict(binding),
                            )
                        )
                    elif label == "deferred":
                        self.assertTrue(
                            binary_output.publish_pending_binary_generation(
                                tmp,
                                expected_current_identity=manifest[
                                    "result_generation_identity"
                                ],
                                expected_activation_identity=activation,
                                publication_guard=lambda: dict(binding),
                            )
                        )

                self.assertEqual(sha256_file.call_count, 0)
                self.assertEqual(verify.call_count, full_proofs)

    def test_recapture_lifecycle_hashes_generation_once_and_authority_twice(self):
        binding = _binding(
            mode="release_recapture_measurement", variant="4"
        )
        activation = hashlib.sha256(b"recapture-lifecycle").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            manifest, validation, _ = self._write_authorized_generation(
                root, binding=binding
            )
            activation_record = {}
            capability_token = (
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                    binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
                )
            )
            root_token = (
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(
                    root
                )
            )
            real_verify = binary_output._verify_pending_generation_integrity
            try:
                with patch.object(
                    binary_output,
                    "_filesystem_supports_direct_seal_fast_path",
                    return_value=True,
                ), patch.object(
                    binary_output,
                    "_verify_pending_generation_integrity",
                    wraps=real_verify,
                ) as generation_verify, patch.object(
                    binary_pipeline,
                    "_verify_performance_authority_gate_binding",
                    return_value=dict(binding),
                ) as authority_verify:
                    binary_pipeline._activate_validated_generation_with_authority_binding(
                        root,
                        manifest,
                        validation,
                        activation_identity=activation,
                        activation_record=activation_record,
                        defer_publication=False,
                        performance_authority_gate_binding=binding,
                    )
                    self.assertEqual(generation_verify.call_count, 1)
                    self.assertFalse(
                        binary_pipeline._discard_measurement_candidate_activation(
                            root,
                            manifest,
                            activation_record,
                            binding,
                        )
                    )
                    self.assertTrue(
                        binary_pipeline._seal_and_finalize_measured_activation(
                            root,
                            manifest,
                            validation,
                            activation_record,
                            binding,
                        )
                    )

                # One live authority derivation is required immediately before
                # each descriptor commit: direct activation and seal.  Pipeline
                # must not duplicate the output layer's independent checks.
                self.assertEqual(authority_verify.call_count, 2)
                self.assertEqual(generation_verify.call_count, 1)
                self.assertTrue(
                    activation_record["activation_recapture_discarded"]
                )
                self.assertIsNone(
                    binary_output.read_active_binary_generation(
                        root, missing_ok=True
                    )
                )
                self.assertIsNone(
                    binary_output.read_pending_binary_generation(
                        root, missing_ok=True
                    )
                )
                self.assertFalse(
                    binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY
                )
            finally:
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                    root_token
                )
                binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                    capability_token
                )

    def test_changed_live_authority_cannot_reach_descriptor_commit(self):
        binding = _binding(mode="release_evidence", variant="5")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            manifest, validation, _ = self._write_authorized_generation(
                root, binding=binding
            )
            changed = binary_pipeline.BinaryPipelineError(
                "BINARY_PERFORMANCE_AUTHORITY_GATE_CHANGED_DURING_RUN",
                "changed before descriptor commit",
            )
            with patch.object(
                binary_pipeline,
                "_verify_performance_authority_gate_binding",
                side_effect=changed,
            ), self.assertRaises(binary_output.BinaryOutputError) as raised:
                binary_pipeline._activate_validated_generation_with_authority_binding(
                    root,
                    manifest,
                    validation,
                    activation_identity="c" * 64,
                    activation_record={},
                    defer_publication=False,
                    performance_authority_gate_binding=binding,
                )

            self.assertEqual(
                raised.exception.reason_code,
                "BINARY_ACTIVE_GENERATION_PUBLICATION_GUARD_MISMATCH",
            )
            self.assertIsNone(
                binary_output.read_active_binary_generation(
                    root, missing_ok=True
                )
            )
            self.assertIsNone(
                binary_output.read_pending_binary_generation(
                    root, missing_ok=True
                )
            )

    def test_direct_activation_rejects_empty_or_wrong_guard_result(self):
        cases = (
            ("none", None),
            ("returns_none", lambda: None),
            ("wrong_binding", lambda: _binding(variant="4")),
        )
        for label, guard in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                manifest, validation, _expected = (
                    self._write_authorized_generation(tmp)
                )
                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.activate_binary_generation(
                        tmp,
                        manifest,
                        validation_result=validation,
                        publication_guard=guard,
                    )
                self.assertFalse(
                    (Path(tmp) / "active_binary_generation.json").exists()
                )

    def test_deferred_publish_rejects_empty_or_wrong_guard_result(self):
        cases = (
            ("none", None),
            ("returns_none", lambda: None),
            ("wrong_binding", lambda: _binding(variant="4")),
        )
        for label, publish_guard in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                manifest, validation, binding = (
                    self._write_authorized_generation(tmp)
                )
                activation_record = {}
                with patch.object(
                    binary_output,
                    "_live_reauthorization_binding_is_current",
                    return_value=True,
                ):
                    binary_output.activate_binary_generation(
                        tmp,
                        manifest,
                        validation_result=validation,
                        defer_publication=True,
                        publication_guard=lambda: dict(binding),
                        activation_record=activation_record,
                    )

                with self.assertRaises(binary_output.BinaryOutputError):
                    binary_output.publish_pending_binary_generation(
                        tmp,
                        expected_current_identity=manifest[
                            "result_generation_identity"
                        ],
                        expected_activation_identity=activation_record[
                            "activation_identity"
                        ],
                        publication_guard=publish_guard,
                    )

                self.assertFalse(
                    (Path(tmp) / "active_binary_generation.json").exists()
                )
                self.assertIsNotNone(
                    binary_output.read_pending_binary_generation(
                        tmp, missing_ok=True
                    )
                )

    def test_release_reauthorization_receipt_covers_direct_and_deferred_boundaries(self):
        for deferred in (False, True):
            with self.subTest(deferred=deferred), tempfile.TemporaryDirectory() as tmp:
                generation_binding = _binding(variant="1")
                current_binding = _binding(variant="4")
                manifest, validation, _binding_value = (
                    self._write_authorized_generation(
                        tmp, binding=generation_binding
                    )
                )
                activation_identity = "a" * 64
                validation_sha256 = hashlib.sha256(
                    Path(validation["validation_result_path"]).read_bytes()
                ).hexdigest()
                receipt = (
                    binary_output.binary_publication_reauthorization_receipt(
                        generation_performance_authority_binding=(
                            generation_binding
                        ),
                        current_performance_authority_binding=current_binding,
                        result_generation_identity=manifest[
                            "result_generation_identity"
                        ],
                        validation_run_identity=validation[
                            "validation_run_identity"
                        ],
                        validation_result_sha256=validation_sha256,
                        activation_identity=activation_identity,
                    )
                )
                activation_record = {}
                with patch.object(
                    binary_output,
                    "_live_reauthorization_binding_is_current",
                    return_value=True,
                ):
                    binary_output.activate_binary_generation(
                        tmp,
                        manifest,
                        validation_result=validation,
                        activation_identity=activation_identity,
                        activation_record=activation_record,
                        defer_publication=deferred,
                        publication_guard=lambda: copy.deepcopy(receipt),
                    )
                    if deferred:
                        self.assertTrue(
                            binary_output.publish_pending_binary_generation(
                                tmp,
                                expected_current_identity=manifest[
                                    "result_generation_identity"
                                ],
                                expected_activation_identity=(
                                    activation_identity
                                ),
                                publication_guard=lambda: copy.deepcopy(
                                    receipt
                                ),
                            )
                        )
                    else:
                        self.assertTrue(
                            binary_output.seal_active_binary_generation(
                                tmp,
                                expected_current_identity=manifest[
                                    "result_generation_identity"
                                ],
                                expected_activation_identity=(
                                    activation_identity
                                ),
                                publication_guard=lambda: copy.deepcopy(
                                    receipt
                                ),
                            )
                        )
                self.assertEqual(
                    binary_output.read_active_binary_generation(tmp)[
                        "result_generation_identity"
                    ],
                    manifest["result_generation_identity"],
                )

    def test_reauthorization_receipt_rejects_modes_replay_types_and_self_signing(self):
        generation_binding = _binding(variant="1")
        current_binding = _binding(variant="4")
        identities = {
            "result_generation_identity": "a" * 64,
            "validation_run_identity": "b" * 64,
            "validation_result_sha256": "c" * 64,
            "activation_identity": "d" * 64,
        }
        receipt = binary_output.binary_publication_reauthorization_receipt(
            generation_performance_authority_binding=generation_binding,
            current_performance_authority_binding=current_binding,
            **identities,
        )

        def accepted(value, *, live=True, **overrides):
            expected = {**identities, **overrides}
            with patch.object(
                binary_output,
                "_live_reauthorization_binding_is_current",
                return_value=live,
            ):
                return binary_output._publication_reauthorization_is_valid(
                    value,
                    expected_generation_binding=generation_binding,
                    **expected,
                )

        self.assertTrue(accepted(receipt))
        self.assertFalse(accepted(receipt, live=False))
        for field in identities:
            with self.subTest(replayed_field=field):
                self.assertFalse(
                    accepted(receipt, **{field: "e" * 64})
                )

        tampered_cases = {}
        missing = copy.deepcopy(receipt)
        missing.pop("activation_identity")
        tampered_cases["missing"] = missing
        extra = copy.deepcopy(receipt)
        extra["extra"] = "x"
        tampered_cases["extra"] = extra
        swapped = copy.deepcopy(receipt)
        swapped[
            "generation_performance_authority_binding"
        ], swapped["current_performance_authority_binding"] = (
            swapped["current_performance_authority_binding"],
            swapped["generation_performance_authority_binding"],
        )
        tampered_cases["swapped_bindings"] = swapped
        alias = copy.deepcopy(receipt)

        class StringAlias(str):
            pass

        alias["activation_identity"] = StringAlias(
            alias["activation_identity"]
        )
        tampered_cases["string_subclass"] = alias
        nested_integer = copy.deepcopy(receipt)
        nested_integer["current_performance_authority_binding"][
            "evidence_sha256"
        ] = 4
        tampered_cases["nested_integer"] = nested_integer
        for candidate in (swapped, alias, nested_integer):
            core = {
                key: value
                for key, value in candidate.items()
                if key != "reauthorization_identity"
            }
            candidate["reauthorization_identity"] = canonical_identity(
                "binary_publication_reauthorization_identity",
                core,
                schema_version="1",
            )
        for label, candidate in tampered_cases.items():
            with self.subTest(tamper=label):
                self.assertFalse(accepted(candidate))

        for mode in (
            "candidate_source_measurement",
            "release_recapture_measurement",
        ):
            with self.subTest(mode=mode), self.assertRaises(
                binary_output.BinaryOutputError
            ):
                binary_output.binary_publication_reauthorization_receipt(
                    generation_performance_authority_binding=_binding(
                        mode=mode, variant="1"
                    ),
                    current_performance_authority_binding=current_binding,
                    **identities,
                )


class PerformanceEvidenceAuthorityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("java") or not shutil.which("javac"):
            raise unittest.SkipTest("full JDK required")
        try:
            asm_jar = binary_asm_helper.resolve_asm_jar()
        except Exception as error:
            raise unittest.SkipTest(str(error)) from error
        fixture = performance_gate_fixtures.BinaryPerformanceGateTest(
            methodName="runTest"
        )
        gate = fixture._currentized_recorded_gate()
        implementation = (
            binary_performance_gate._performance_implementation_protocol(
                asm_jar
            )
        )
        protocol = gate["measurement_protocol"]
        protocol["implementation"] = dict(implementation)
        protocol["source_implementation_identity"] = implementation[
            "source_implementation_identity"
        ]
        protocol["runtime_implementation_identity"] = implementation[
            "runtime_implementation_identity"
        ]
        gate["recorded_measurements"]["captured_at"] = (
            "2026-08-13T00:00:00Z"
        )
        for probe_name in _PROBE_NAMES:
            probe = gate["recorded_measurements"][probe_name]
            probe["captured_at"] = "2026-08-13T00:00:00Z"
            probe["performance_authority_mode"] = (
                "candidate_source_measurement"
            )
            probe["activation_authority_mode"] = (
                "candidate_source_measurement"
            )
            probe["activation_candidate_discarded"] = True
            probe["activation_recapture_discarded"] = False
            authority_binding = probe[
                "pipeline_performance_authority_binding"
            ]
            authority_binding["authority_mode"] = (
                "candidate_source_measurement"
            )
            authority_binding["source_implementation_identity"] = (
                implementation["source_implementation_identity"]
            )
            authority_binding["binding_identity"] = canonical_identity(
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
        gate["measurement_provisional"] = {
            "schema": (
                "java-upgrade-analyzer.binary-performance-provisional.v1"
            ),
            "purpose": "isolated_release_path_recapture_only",
            "source_implementation_identity": implementation[
                "source_implementation_identity"
            ],
            "runtime_implementation_identity": implementation[
                "runtime_implementation_identity"
            ],
            "dataset_identity": protocol["dataset_identity"],
            "candidate_probe_authority_mode": (
                "candidate_source_measurement"
            ),
            "candidate_result_sha256": "9" * 64,
            "public_activation_allowed": False,
        }
        cls.candidate_gate = gate
        cls.current_implementation = implementation

    def test_changing_only_candidate_mode_strings_cannot_become_final(self):
        baseline = binary_performance_gate.evaluate_provisional_gate(
            copy.deepcopy(self.candidate_gate),
            _current_source_implementation=self.current_implementation,
        )
        self.assertEqual(baseline["status"], "passed", baseline["issues"])

        relabeled = copy.deepcopy(self.candidate_gate)
        relabeled.pop("measurement_provisional")
        for probe_name in _PROBE_NAMES:
            probe = relabeled["recorded_measurements"][probe_name]
            probe["performance_authority_mode"] = (
                "release_recapture_measurement"
            )
            probe["activation_authority_mode"] = (
                "release_recapture_measurement"
            )

        verification = binary_performance_gate.evaluate_recorded_gate(
            relabeled,
            _current_source_implementation=self.current_implementation,
            _require_live_runtime_implementation=True,
        )

        self.assertEqual(verification["status"], "failed")
        fields = {item.get("field") for item in verification["issues"]}
        self.assertTrue(any(
            field and (
                "pipeline_performance_authority_binding" in field
                or "activation_candidate_discarded" in field
                or "activation_recapture_discarded" in field
            )
            for field in fields
        ), verification["issues"])

    def test_provisional_runtime_identity_must_match_live_implementation(self):
        forged = copy.deepcopy(self.candidate_gate)
        protocol = forged["measurement_protocol"]
        implementation = protocol["implementation"]
        implementation["pipeline_generation_implementation_identity"] = (
            "8" * 64
        )
        implementation["runtime_implementation_identity"] = (
            binary_performance_gate._runtime_implementation_identity(
                implementation
            )
        )
        protocol["runtime_implementation_identity"] = implementation[
            "runtime_implementation_identity"
        ]
        forged["measurement_provisional"][
            "runtime_implementation_identity"
        ] = implementation["runtime_implementation_identity"]

        verification = binary_performance_gate.evaluate_provisional_gate(
            forged,
            _current_source_implementation=self.current_implementation,
        )

        self.assertEqual(verification["status"], "failed")
        self.assertTrue(any(
            item.get("reason_code")
            == "BINARY_PERFORMANCE_RECORDED_IMPLEMENTATION_MISMATCH"
            and (
                item.get("field")
                == "pipeline_generation_implementation_identity"
                or "pipeline_generation_implementation_identity"
                in str(item.get("field") or "")
            )
            for item in verification["issues"]
        ), verification["issues"])

    def test_percentiles_canonicalize_valid_integer_json_samples(self):
        self.assertIs(
            type(binary_performance_gate._p50([1, 1, 1])), float
        )
        self.assertIs(
            type(binary_performance_gate._p95([1, 1, 1])), float
        )

    def test_sha256_identities_cannot_be_json_integers(self):
        forged = copy.deepcopy(self.candidate_gate)
        for probe_name in _PROBE_NAMES:
            binding = forged["recorded_measurements"][probe_name][
                "pipeline_performance_authority_binding"
            ]
            binding["support_contract_identity"] = int("8" * 64)
            binding["binding_identity"] = canonical_identity(
                "binary_performance_authority_binding_identity",
                {
                    "support_contract_identity": binding[
                        "support_contract_identity"
                    ],
                    "evidence_sha256": binding["evidence_sha256"],
                    "source_implementation_identity": binding[
                        "source_implementation_identity"
                    ],
                    "authority_mode": binding["authority_mode"],
                },
                schema_version="1",
            )

        verification = binary_performance_gate.evaluate_provisional_gate(
            forged,
            _current_source_implementation=self.current_implementation,
        )

        self.assertEqual(verification["status"], "failed")
        self.assertTrue(any(
            "pipeline_performance_authority_binding"
            in str(item.get("field") or "")
            for item in verification["issues"]
        ), verification["issues"])

    def _provisional_and_recapture(self):
        candidate = _candidate_raw_result(self.candidate_gate)
        candidate_content = json.dumps(
            candidate, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        with patch.object(
            binary_performance_gate,
            "resolve_asm_jar",
            return_value=Path("/fixture/asm.jar"),
        ), patch.object(
            binary_performance_gate,
            "_performance_implementation_protocol",
            return_value=self.current_implementation,
        ):
            provisional = (
                binary_performance_gate.build_recorded_gate_from_result(
                    candidate_content,
                    captured_at="2026-08-18T00:00:00Z",
                    provisional=True,
                )
            )
        # Deliberately use pretty JSON plus a newline.  The contract binds
        # exact supplied bytes, not a reserialized semantic object.
        provisional_content = (
            json.dumps(
                provisional, ensure_ascii=False, indent=2, sort_keys=True
            ) + "\n"
        ).encode("utf-8")
        recapture = _recapture_raw_result(
            candidate, provisional_content
        )
        return provisional_content, recapture

    def _build_provisional_from_raw(self, candidate):
        candidate_content = json.dumps(
            candidate, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        with patch.object(
            binary_performance_gate,
            "resolve_asm_jar",
            return_value=Path("/fixture/asm.jar"),
        ), patch.object(
            binary_performance_gate,
            "_performance_implementation_protocol",
            return_value=self.current_implementation,
        ):
            return binary_performance_gate.build_recorded_gate_from_result(
                candidate_content,
                captured_at="2026-08-18T00:00:00Z",
                provisional=True,
            )

    @staticmethod
    def _diverge_changed_probe_binding(raw, field, value):
        binding = raw["measurements"][
            "changed_full_pipeline_probe"
        ]["pipeline_performance_authority_binding"]
        binding[field] = value
        if field != "binding_identity":
            _refresh_binding_identity(binding)
        return binding

    def test_candidate_builder_rejects_each_divergent_probe_binding_component(self):
        cases = (
            ("support_contract_identity", "a" * 64),
            ("evidence_sha256", "b" * 64),
            ("source_implementation_identity", "c" * 64),
            ("binding_identity", "d" * 64),
        )
        for field, value in cases:
            with self.subTest(field=field):
                forged = _candidate_raw_result(self.candidate_gate)
                binding = self._diverge_changed_probe_binding(
                    forged, field, value
                )
                if field in {
                    "support_contract_identity", "evidence_sha256",
                }:
                    self.assertTrue(
                        binary_performance_gate
                        ._performance_authority_binding_is_valid(
                            binding,
                            expected_mode=(
                                binary_performance_gate
                                ._CANDIDATE_PROBE_AUTHORITY_MODE
                            ),
                            expected_source_identity=(
                                self.current_implementation[
                                    "source_implementation_identity"
                                ]
                            ),
                        )
                    )
                with self.assertRaises(
                    binary_performance_gate.PerformanceGateError
                ) as caught:
                    self._build_provisional_from_raw(forged)

                self.assertEqual(
                    caught.exception.failure.get("reason_code"),
                    "BINARY_PERFORMANCE_RAW_RESULT_INVALID",
                )
                self.assertIn(
                    "pipeline_performance_authority_binding",
                    str(caught.exception.failure.get("field") or ""),
                )

    def _build_final(self, provisional_content, recapture):
        policy = binary_performance_gate.release_policy()
        reference = policy["reference_implementation"]
        reference["pipeline_generation_implementation_identity"] = (
            self.current_implementation[
                "pipeline_generation_implementation_identity"
            ]
        )
        reference["validator_implementation_identity"] = (
            self.current_implementation["validator_implementation_identity"]
        )
        recapture_content = json.dumps(
            recapture, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        with patch.object(
            binary_performance_gate,
            "resolve_asm_jar",
            return_value=Path("/fixture/asm.jar"),
        ), patch.object(
            binary_performance_gate,
            "_performance_implementation_protocol",
            return_value=self.current_implementation,
        ), patch.object(
            binary_performance_gate, "release_policy", return_value=policy,
        ):
            return binary_performance_gate.build_recorded_gate_from_result(
                recapture_content,
                captured_at="2026-08-18T01:00:00Z",
                provisional=False,
                provisional_gate_content=provisional_content,
            )

    def test_final_builder_binds_exact_provisional_bytes(self):
        provisional_content, recapture = self._provisional_and_recapture()

        final = self._build_final(provisional_content, recapture)
        self.assertEqual(final["status"], "passed")

        with self.assertRaises(
            binary_performance_gate.PerformanceGateError
        ) as caught:
            self._build_final(provisional_content + b"\n", recapture)
        self.assertIn("not bound to the supplied provisional bytes", str(
            caught.exception
        ))

    def test_final_builder_rejects_one_wrong_probe_sha_or_source(self):
        provisional_content, recapture = self._provisional_and_recapture()
        cases = (
            ("evidence_sha256", "a" * 64),
            ("source_implementation_identity", "b" * 64),
        )
        for field, value in cases:
            with self.subTest(field=field):
                forged = copy.deepcopy(recapture)
                binding = forged["measurements"][
                    "changed_full_pipeline_probe"
                ]["pipeline_performance_authority_binding"]
                binding[field] = value
                binding["binding_identity"] = canonical_identity(
                    "binary_performance_authority_binding_identity",
                    {
                        "support_contract_identity": binding[
                            "support_contract_identity"
                        ],
                        "evidence_sha256": binding["evidence_sha256"],
                        "source_implementation_identity": binding[
                            "source_implementation_identity"
                        ],
                        "authority_mode": binding["authority_mode"],
                    },
                    schema_version="1",
                )
                with self.assertRaises(
                    binary_performance_gate.PerformanceGateError
                ):
                    self._build_final(provisional_content, forged)

    def test_final_builder_rejects_inconsistent_probe_bindings(self):
        provisional_content, recapture = self._provisional_and_recapture()
        forged = copy.deepcopy(recapture)
        binding = forged["measurements"][
            "changed_full_pipeline_probe"
        ]["pipeline_performance_authority_binding"]
        binding["support_contract_identity"] = "a" * 64
        binding["binding_identity"] = canonical_identity(
            "binary_performance_authority_binding_identity",
            {
                "support_contract_identity": binding[
                    "support_contract_identity"
                ],
                "evidence_sha256": binding["evidence_sha256"],
                "source_implementation_identity": binding[
                    "source_implementation_identity"
                ],
                "authority_mode": binding["authority_mode"],
            },
            schema_version="1",
        )

        with self.assertRaises(
            binary_performance_gate.PerformanceGateError
        ) as caught:
            self._build_final(provisional_content, forged)
        issues = caught.exception.failure.get("issues") or []
        raw_field = str(caught.exception.failure.get("field") or "")
        self.assertTrue(
            raw_field.endswith("pipeline_performance_authority_binding")
            or any(
                item.get("field")
                == "pipeline_performance_authority_binding.consistency"
                for item in issues
            ),
            caught.exception.failure,
        )

    def test_final_builder_rejects_each_divergent_probe_binding_component(self):
        cases = (
            ("support_contract_identity", "a" * 64),
            ("evidence_sha256", "b" * 64),
            ("source_implementation_identity", "c" * 64),
            ("binding_identity", "d" * 64),
        )
        for field, value in cases:
            with self.subTest(field=field):
                provisional_content, recapture = (
                    self._provisional_and_recapture()
                )
                binding = self._diverge_changed_probe_binding(
                    recapture, field, value
                )
                if field == "support_contract_identity":
                    self.assertTrue(
                        binary_performance_gate
                        ._performance_authority_binding_is_valid(
                            binding,
                            expected_mode=(
                                binary_performance_gate
                                ._RELEASE_RECAPTURE_PROBE_AUTHORITY_MODE
                            ),
                            expected_source_identity=(
                                self.current_implementation[
                                    "source_implementation_identity"
                                ]
                            ),
                        )
                    )
                with self.assertRaises(
                    binary_performance_gate.PerformanceGateError
                ) as caught:
                    self._build_final(provisional_content, recapture)

                self.assertEqual(
                    caught.exception.failure.get("reason_code"),
                    "BINARY_PERFORMANCE_RAW_RESULT_INVALID",
                )
                self.assertIn(
                    "pipeline_performance_authority_binding",
                    str(caught.exception.failure.get("field") or ""),
                )

    def test_builder_rejects_json_type_aliases_nan_and_duplicate_keys(self):
        baseline = _candidate_raw_result(self.candidate_gate)

        def protocol_type(raw):
            raw["measurement_protocol"]["jar_count"] = True

        def numeric_string(raw):
            raw["measurements"]["cold"]["end_to_end_seconds"] = "1.0"

        def integer_boolean(raw):
            raw["measurements"]["cold"]["parser_invocations"] = False

        def probe_pid_boolean(raw):
            raw["measurements"]["full_pipeline_probe"]["process_id"] = True

        def integer_sha(raw):
            for probe_name in _PROBE_NAMES:
                binding = raw["measurements"][probe_name][
                    "pipeline_performance_authority_binding"
                ]
                binding["support_contract_identity"] = int("8" * 64)
                binding["binding_identity"] = canonical_identity(
                    "binary_performance_authority_binding_identity",
                    {
                        "support_contract_identity": binding[
                            "support_contract_identity"
                        ],
                        "evidence_sha256": binding["evidence_sha256"],
                        "source_implementation_identity": binding[
                            "source_implementation_identity"
                        ],
                        "authority_mode": binding["authority_mode"],
                    },
                    schema_version="1",
                )

        cases = (
            ("protocol boolean", protocol_type),
            ("numeric string", numeric_string),
            ("integer boolean", integer_boolean),
            ("probe pid boolean", probe_pid_boolean),
            ("integer SHA", integer_sha),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                raw = copy.deepcopy(baseline)
                mutate(raw)
                content = json.dumps(
                    raw, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                with patch.object(
                    binary_performance_gate,
                    "resolve_asm_jar",
                    return_value=Path("/fixture/asm.jar"),
                ), patch.object(
                    binary_performance_gate,
                    "_performance_implementation_protocol",
                    return_value=self.current_implementation,
                ), self.assertRaises(
                    binary_performance_gate.PerformanceGateError
                ):
                    binary_performance_gate.build_recorded_gate_from_result(
                        content,
                        captured_at="2026-08-18T00:00:00Z",
                        provisional=True,
                    )

        valid_content = json.dumps(
            baseline, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        noncanonical_contents = (
            (
                "NaN",
                valid_content.replace(
                    b'"cpu_seconds":0.5', b'"cpu_seconds":NaN', 1
                ),
            ),
            (
                "duplicate key",
                b'{"status":"measured",' + valid_content[1:],
            ),
        )
        for label, content in noncanonical_contents:
            with self.subTest(label=label), self.assertRaises(
                binary_performance_gate.PerformanceGateError
            ):
                binary_performance_gate.build_recorded_gate_from_result(
                    content,
                    captured_at="2026-08-18T00:00:00Z",
                    provisional=True,
                )

        with self.assertRaises(binary_performance_gate.PerformanceGateError):
            binary_performance_gate.build_recorded_gate_from_result(
                valid_content,
                captured_at="2026-08-18T00:00:00Z",
                provisional=1,
            )
        with self.assertRaises(binary_performance_gate.PerformanceGateError):
            binary_performance_gate.build_recorded_gate_from_result(
                valid_content.decode("utf-8"),
                captured_at="2026-08-18T00:00:00Z",
                provisional=True,
            )


class PerformanceCheckpointResidualTest(unittest.TestCase):
    def _exercise_cleanup(self, *, mode, checkpoint_kind):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "probe-output"
            checkpoint = (
                root
                / "binary_observability"
                / "validation_checkpoint.json"
            )
            checkpoint.parent.mkdir(parents=True)
            external = Path(tmp).resolve() / "external-checkpoint-target.json"
            external.write_text("external-sentinel", encoding="utf-8")
            if checkpoint_kind == "invalid_json":
                checkpoint.write_text("{invalid", encoding="utf-8")
            elif checkpoint_kind == "empty_object":
                checkpoint.write_text("{}\n", encoding="utf-8")
            elif checkpoint_kind == "symlink":
                try:
                    checkpoint.symlink_to(external)
                except OSError as error:
                    self.skipTest(f"file symlinks are unavailable: {error}")
            else:
                raise AssertionError(checkpoint_kind)

            raised = None
            if mode == "candidate":
                token = (
                    binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT
                    .set(
                        binary_pipeline
                        ._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CAPABILITY
                    )
                )
                cleanup = binary_pipeline._cleanup_performance_measurement_state
                reset = lambda: (
                    binary_pipeline._PERFORMANCE_MEASUREMENT_BOOTSTRAP_CONTEXT
                    .reset(token)
                )
            elif mode == "recapture":
                capability_token = (
                    binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.set(
                        binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CAPABILITY
                    )
                )
                root_token = (
                    binary_pipeline
                    ._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.set(root)
                )
                cleanup = binary_pipeline._cleanup_performance_recapture_state

                def reset():
                    binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_ROOT_CONTEXT.reset(
                        root_token
                    )
                    binary_pipeline._PERFORMANCE_RELEASE_RECAPTURE_CONTEXT.reset(
                        capability_token
                    )
            else:
                raise AssertionError(mode)
            try:
                try:
                    cleanup(root)
                except binary_pipeline.BinaryPipelineError as error:
                    raised = error
            finally:
                reset()

            residual = checkpoint.exists() or checkpoint.is_symlink()
            self.assertTrue(
                raised is not None or not residual,
                (
                    f"{mode} cleanup silently accepted a residual "
                    f"{checkpoint_kind} checkpoint"
                ),
            )
            self.assertEqual(
                external.read_text(encoding="utf-8"),
                "external-sentinel",
            )

    def test_candidate_and_recapture_cleanup_fail_closed_on_residuals(self):
        for mode in ("candidate", "recapture"):
            for checkpoint_kind in (
                "invalid_json",
                "empty_object",
                "symlink",
            ):
                with self.subTest(mode=mode, checkpoint_kind=checkpoint_kind):
                    self._exercise_cleanup(
                        mode=mode,
                        checkpoint_kind=checkpoint_kind,
                    )

    def test_probe_does_not_report_empty_checkpoint_object_as_absent(self):
        evidence = {
            "class_count": 1,
            "base_class_count": 1,
            "current_class_count": 1,
            "validation_status": "passed",
            "validation_issue_count": 0,
            "authoritative_change_fact_count": 0,
            "authoritative_member_change_kind_counts": {},
            "formal_api_result_count": 0,
            "formal_reachability_status_counts": {},
            "formal_impact_conclusion_counts": {},
        }

        def fake_pipeline(_config, *, output_root, **_kwargs):
            output_root = Path(output_root)
            checkpoint = (
                output_root
                / "binary_observability"
                / "validation_checkpoint.json"
            )
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text("{}\n", encoding="utf-8")
            return {
                "total_elapsed_seconds": 0.1,
                "total_elapsed_scope": "current_pipeline_attempt",
                "phase_timings_scope": "current_pipeline_attempt",
                "phase_timings": [{
                    "phase": "validated_generation_activation",
                    "elapsed_seconds": 0.01,
                    "peak_rss_bytes": 1,
                    "activation_authority_mode": (
                        "candidate_source_measurement"
                    ),
                    "publication_deferred": False,
                    "checkpoint_retained": False,
                    "activation_candidate_discarded": True,
                }],
                "peak_rss_bytes": 1,
                "performance_authority_gate_binding": {},
                "cache_metrics": {
                    "classfile_parser_invocations": 1,
                    "artifact_snapshot_hits": 0,
                    "artifact_snapshot_disk_hits": 0,
                    "artifact_snapshot_memory_hits": 0,
                },
            }

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_performance_gate, "_jdk_home", return_value=Path("/jdk")
        ), patch.object(
            binary_performance_gate,
            "_full_pipeline_evidence",
            return_value=evidence,
        ), patch.object(
            binary_pipeline, "run_pipeline", side_effect=fake_pipeline
        ):
            with self.assertRaises(
                binary_performance_gate.PerformanceGateError
            ):
                binary_performance_gate._full_pipeline_probe(
                    [{"path": "/fixture/a.jar", "sha256": "a" * 64}],
                    root=Path(tmp),
                    asm_jar=Path("/asm.jar"),
                    classes_per_jar=1,
                )


class PerformanceProbeWorkerBoundaryTest(unittest.TestCase):
    def _valid_spec(self, root):
        asm_jar = Path(root) / "asm.jar"
        asm_jar.write_bytes(b"asm-boundary-fixture")
        return {
            "schema": binary_performance_gate.PROBE_WORKER_SCHEMA,
            "artifacts": [_worker_artifact(root)],
            "current_artifacts": None,
            "asm_jar": str(asm_jar.resolve()),
            "classes_per_jar": 1,
            "expected_implementation": _worker_implementation(),
            "provisional_gate_path": "",
        }

    def _run_worker(self, root, content):
        worker_input = Path(root) / "worker-input.json"
        worker_output = Path(root) / "worker-output.json"
        worker_input.write_bytes(content)
        implementation = _worker_implementation()
        raw_result = _worker_probe_result(implementation)
        raw_result.pop("performance_authority_mode")
        with patch.object(
            binary_performance_gate,
            "_performance_implementation_protocol",
            return_value=implementation,
        ), patch.object(
            binary_performance_gate,
            "_candidate_performance_authority",
            side_effect=_worker_candidate_authority,
        ), patch.object(
            binary_performance_gate,
            "_full_pipeline_probe",
            return_value=raw_result,
        ) as full_probe:
            returncode = binary_performance_gate._run_probe_worker(
                worker_input, worker_output
            )
        response = json.loads(worker_output.read_text(encoding="utf-8"))
        return returncode, response, full_probe

    def test_worker_rejects_lossy_input_normalization_before_probe(self):
        def mutate_artifact(field, value):
            def mutate(spec):
                spec["artifacts"][0][field] = value
            return mutate

        cases = (
            ("boolean classes", lambda spec: spec.update(
                classes_per_jar=True
            )),
            ("string classes", lambda spec: spec.update(
                classes_per_jar="1"
            )),
            ("float classes", lambda spec: spec.update(
                classes_per_jar=1.0
            )),
            ("string artifacts", lambda spec: spec.update(
                artifacts="artifact.jar"
            )),
            ("empty artifacts", lambda spec: spec.update(artifacts=[])),
            ("string current artifacts", lambda spec: spec.update(
                current_artifacts="artifact.jar"
            )),
            ("implementation pairs", lambda spec: spec.update(
                expected_implementation=list(
                    spec["expected_implementation"].items()
                )
            )),
            ("numeric asm path", lambda spec: spec.update(asm_jar=1)),
            ("array provisional path", lambda spec: spec.update(
                provisional_gate_path=[]
            )),
            ("numeric artifact path", mutate_artifact("path", 1)),
            ("invalid artifact digest", mutate_artifact(
                "sha256", "not-a-digest"
            )),
            ("boolean artifact length", mutate_artifact(
                "byte_length", True
            )),
            ("string artifact index", mutate_artifact("jar_index", "0")),
            ("boolean first class", mutate_artifact(
                "first_class_index", False
            )),
            ("string class count", mutate_artifact("class_count", "1")),
            ("unknown artifact field", lambda spec: spec["artifacts"][0].update(
                unknown="untrusted"
            )),
        )
        for label, mutate in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                spec = self._valid_spec(tmp)
                mutate(spec)
                returncode, response, full_probe = self._run_worker(
                    tmp,
                    json.dumps(spec, allow_nan=True).encode("utf-8"),
                )
                self.assertEqual(returncode, 1, response)
                self.assertEqual(response.get("status"), "failed", response)
                self.assertIsInstance(response.get("failure"), dict)
                self.assertTrue(
                    response["failure"].get("reason_code"), response
                )
                full_probe.assert_not_called()

    def test_worker_rejects_nan_and_duplicate_json_before_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = self._valid_spec(tmp)
            spec["artifacts"][0]["byte_length"] = float("nan")
            nan_content = json.dumps(spec, allow_nan=True).encode("utf-8")
            returncode, response, full_probe = self._run_worker(
                tmp, nan_content
            )
            self.assertEqual(returncode, 1, response)
            self.assertEqual(response.get("status"), "failed", response)
            full_probe.assert_not_called()

        with tempfile.TemporaryDirectory() as tmp:
            spec = self._valid_spec(tmp)
            content = json.dumps(spec).replace(
                '"classes_per_jar": 1',
                '"classes_per_jar": false, "classes_per_jar": 1',
            ).encode("utf-8")
            returncode, response, full_probe = self._run_worker(tmp, content)
            self.assertEqual(returncode, 1, response)
            self.assertEqual(response.get("status"), "failed", response)
            full_probe.assert_not_called()

    def test_worker_rejects_external_root_without_touching_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            external = root / "external-root"
            external.mkdir()
            sentinel = external / "sentinel.txt"
            sentinel.write_text("must-survive", encoding="utf-8")
            spec = self._valid_spec(root)
            spec["root"] = str(external)

            returncode, response, full_probe = self._run_worker(
                root, json.dumps(spec).encode("utf-8")
            )

            self.assertEqual(returncode, 1, response)
            self.assertEqual(response.get("status"), "failed", response)
            full_probe.assert_not_called()
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"), "must-survive"
            )
            self.assertEqual(
                sorted(path.name for path in external.iterdir()),
                ["sentinel.txt"],
            )

    def _run_parent_reader(
        self, root, response_content, *, current_artifacts=None,
    ):
        def fake_subprocess(argv, **_kwargs):
            output = Path(argv[argv.index("--probe-worker-output") + 1])
            output.write_bytes(response_content)
            return SimpleNamespace(returncode=0, stderr="")

        with patch.object(
            binary_performance_gate,
            "run_managed_subprocess",
            side_effect=fake_subprocess,
        ):
            return binary_performance_gate._run_isolated_full_pipeline_probe(
                [_worker_artifact(root)],
                root=Path(root),
                asm_jar=Path(root) / "asm.jar",
                classes_per_jar=1,
                expected_implementation=_worker_implementation(),
                current_artifacts=current_artifacts,
            )

    def test_parent_rejects_noncanonical_or_inexact_worker_output(self):
        implementation = _worker_implementation()
        valid_result = _worker_probe_result(implementation)
        schema = binary_performance_gate.PROBE_WORKER_SCHEMA

        def passed(result, **extra):
            return {
                "schema": schema,
                "status": "passed",
                "result": result,
                **extra,
            }

        extra_result = copy.deepcopy(valid_result)
        extra_result["unknown"] = "untrusted"
        missing_result = copy.deepcopy(valid_result)
        missing_result.pop("validation_status")
        boolean_pid = copy.deepcopy(valid_result)
        boolean_pid["process_id"] = True
        nan_result = copy.deepcopy(valid_result)
        nan_result["phase_seconds"][next(iter(
            binary_performance_gate.FULL_PIPELINE_PHASES
        ))] = float("nan")
        semantic_mutations = []
        for label, field, value in (
            ("failed result status", "status", "failed"),
            ("wrong comparison", "comparison", "untrusted"),
            ("wrong jar count", "jar_count", 2),
            ("wrong current jar count", "current_jar_count", 2),
            ("wrong expected class count", "expected_class_count", 2),
            ("wrong RSS scope", "rss_measurement_scope", "untrusted"),
            (
                "wrong pipeline timing scope",
                "pipeline_total_elapsed_scope",
                "untrusted",
            ),
            (
                "wrong phase timing scope",
                "pipeline_phase_timings_scope",
                "untrusted",
            ),
            ("publication marked deferred", "publication_deferred", True),
            ("checkpoint marked retained", "checkpoint_retained", True),
            (
                "candidate activation not discarded",
                "activation_candidate_discarded",
                False,
            ),
            ("active generation present", "active_generation_absent", False),
            ("pending generation present", "pending_generation_absent", False),
            (
                "validation checkpoint present",
                "validation_checkpoint_absent",
                False,
            ),
            ("failed validation", "validation_status", "failed"),
            ("validation issues", "validation_issue_count", 1),
            ("cache total mismatch", "artifact_snapshot_hits", 1),
            ("peak RSS mismatch", "peak_rss_bytes", 2),
            (
                "pipeline exceeds outer wall",
                "pipeline_reported_seconds",
                0.3,
            ),
        ):
            mutated = copy.deepcopy(valid_result)
            mutated[field] = value
            semantic_mutations.append((label, json.dumps(passed(mutated))))
        phase_total = copy.deepcopy(valid_result)
        phase_total["phase_seconds"] = {
            name: 1.0
            for name in binary_performance_gate.FULL_PIPELINE_PHASES
        }
        semantic_mutations.append((
            "phase total exceeds pipeline wall",
            json.dumps(passed(phase_total)),
        ))
        descending_phase_peak = copy.deepcopy(valid_result)
        ordered_phases = list(binary_performance_gate.FULL_PIPELINE_PHASES)
        descending_phase_peak["phase_peak_rss_bytes"][ordered_phases[0]] = 2
        descending_phase_peak["peak_rss_bytes"] = 2
        semantic_mutations.append((
            "phase RSS high-water mark decreases",
            json.dumps(passed(descending_phase_peak)),
        ))
        nonmonotonic_peak = copy.deepcopy(valid_result)
        ordered_phases = list(binary_performance_gate.FULL_PIPELINE_PHASES)
        nonmonotonic_peak["phase_peak_rss_bytes"] = {
            name: 2 for name in ordered_phases
        }
        nonmonotonic_peak["phase_peak_rss_bytes"][ordered_phases[1]] = 1
        nonmonotonic_peak["post_pipeline_peak_rss_bytes"] = 2
        nonmonotonic_peak["peak_rss_bytes"] = 2
        semantic_mutations.append((
            "phase RSS high-water decreases",
            json.dumps(passed(nonmonotonic_peak)),
        ))
        histogram_total = copy.deepcopy(valid_result)
        histogram_total["authoritative_change_fact_count"] = 1
        semantic_mutations.append((
            "authoritative histogram mismatch",
            json.dumps(passed(histogram_total)),
        ))
        wrong_histogram_distribution = copy.deepcopy(valid_result)
        wrong_histogram_distribution[
            "authoritative_member_change_kind_counts"
        ] = {"untrusted": 0}
        semantic_mutations.append((
            "wrong fixed-fixture histogram distribution",
            json.dumps(passed(wrong_histogram_distribution)),
        ))
        cases = (
            ("unknown result field", json.dumps(passed(extra_result))),
            ("missing result field", json.dumps(passed(missing_result))),
            ("boolean process id", json.dumps(passed(boolean_pid))),
            (
                "nested NaN",
                json.dumps(passed(nan_result), allow_nan=True),
            ),
            (
                "extra success field",
                json.dumps(passed(valid_result, failure={"detail": "x"})),
            ),
            (
                "malformed failure",
                json.dumps({
                    "schema": schema,
                    "status": "failed",
                    "failure": "not-an-object",
                }),
            ),
            *semantic_mutations,
        )
        duplicate = json.dumps(passed(valid_result)).replace(
            '"status": "passed"',
            '"status": "failed", "status": "passed"',
            1,
        )
        cases = (*cases, ("duplicate response key", duplicate))

        for label, content in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(
                    binary_performance_gate.PerformanceGateError
                ) as caught:
                    self._run_parent_reader(tmp, content.encode("utf-8"))
                self.assertIsInstance(caught.exception.failure, dict)
                self.assertTrue(
                    caught.exception.failure.get("reason_code"),
                    caught.exception.failure,
                )

    def test_parent_rejects_wrong_changed_probe_distributions(self):
        implementation = _worker_implementation()
        valid = _worker_probe_result(implementation)
        valid.update({
            "comparison": "nonidentical-base-current-cold-output",
            "parser_invocations": 2,
            "authoritative_change_fact_count": 1,
            "authoritative_member_change_kind_counts": {
                "implementation_changed": 1,
            },
            "formal_api_result_count": 1,
            "formal_reachability_status_counts": {
                "not_found_in_static_analysis": 1,
            },
            "formal_impact_conclusion_counts": {"inconclusive": 1},
        })
        schema = binary_performance_gate.PROBE_WORKER_SCHEMA
        for field in (
            "authoritative_member_change_kind_counts",
            "formal_reachability_status_counts",
            "formal_impact_conclusion_counts",
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                current = [_worker_changed_artifact(tmp)]
                forged = copy.deepcopy(valid)
                forged[field] = {"wrong_but_same_total": 1}
                response = json.dumps({
                    "schema": schema,
                    "status": "passed",
                    "result": forged,
                }).encode("utf-8")
                with self.assertRaises(
                    binary_performance_gate.PerformanceGateError
                ):
                    self._run_parent_reader(
                        tmp, response, current_artifacts=current
                    )


class PerformanceEvidenceCliBoundaryTest(unittest.TestCase):
    def _run_main(self, argv):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            try:
                return binary_performance_gate.main(argv)
            except SystemExit as error:
                return int(error.code or 0)

    def test_builder_cannot_overwrite_its_raw_input(self):
        original = b'{"schema":"raw-input-sentinel"}\n'
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "candidate-result.json"
            raw.write_bytes(original)
            with patch.object(
                binary_performance_gate,
                "build_recorded_gate_from_result",
                return_value={"schema": "forged-success"},
            ) as builder:
                returncode = self._run_main([
                    "--build-provisional-from-result", str(raw),
                    "--captured-at", "2026-08-18T00:00:00Z",
                    "--output", str(raw),
                ])

            self.assertNotEqual(returncode, 0)
            self.assertEqual(raw.read_bytes(), original)
            builder.assert_not_called()

    def test_final_builder_cannot_overwrite_its_provisional_input(self):
        provisional_content = b'{"schema":"provisional-sentinel"}\n'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "recapture-result.json"
            raw.write_text("{}\n", encoding="utf-8")
            provisional = root / "provisional-gate.json"
            provisional.write_bytes(provisional_content)
            with patch.object(
                binary_performance_gate,
                "build_recorded_gate_from_result",
                return_value={"schema": "forged-success"},
            ) as builder:
                returncode = self._run_main([
                    "--build-final-from-result", str(raw),
                    "--provisional-gate", str(provisional),
                    "--captured-at", "2026-08-18T01:00:00Z",
                    "--output", str(provisional),
                ])

            self.assertNotEqual(returncode, 0)
            self.assertEqual(provisional.read_bytes(), provisional_content)
            builder.assert_not_called()

    def test_failed_build_replaces_stale_success_output_with_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "candidate-result.json"
            raw.write_text("{}\n", encoding="utf-8")
            output = root / "performance-gate.json"
            output.write_text(
                '{"schema":"stale","status":"passed"}\n',
                encoding="utf-8",
            )
            with patch.object(
                binary_performance_gate,
                "build_recorded_gate_from_result",
                side_effect=binary_performance_gate.PerformanceGateError(
                    "injected invalid raw evidence"
                ),
            ):
                returncode = self._run_main([
                    "--build-provisional-from-result", str(raw),
                    "--captured-at", "2026-08-18T00:00:00Z",
                    "--output", str(output),
                ])

            persisted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(returncode, 1)
            self.assertEqual(persisted.get("status"), "failed")
            self.assertEqual(
                persisted.get("schema"),
                (
                    "java-upgrade-analyzer."
                    "binary-performance-evidence-build-failure.v1"
                ),
            )


if __name__ == "__main__":
    unittest.main()
