import csv
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import errno
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zlib
from contextlib import contextmanager, nullcontext
from pathlib import Path
from unittest.mock import Mock, patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from binary_decision_engine import BinaryDecisionBundle  # noqa: E402
from binary_first_contract import (  # noqa: E402
    canonical_identity,
    canonical_identity_streaming,
)
from binary_first_model import ActiveSnapshot, RuntimeProfile  # noqa: E402
from binary_output import (  # noqa: E402
    BinaryOutputError,
    _aggregate_by_api,
    _result_generation_identity_from_manifest,
    activate_binary_generation,
    compare_and_restore_active_binary_generation,
    seal_active_binary_generation,
    write_binary_generation,
)
from binary_report import BinaryReportError, load_validated_generation  # noqa: E402
from binary_trace_engine import BinaryTraceBundle  # noqa: E402
import binary_report  # noqa: E402
import binary_output  # noqa: E402
import binary_validation_contract as validation_contract  # noqa: E402
import process_lock  # noqa: E402
from process_lock import exclusive_file_lock  # noqa: E402
from signature_utils import jvm_method_parameter_signature  # noqa: E402


class BinaryOutputTest(unittest.TestCase):
    def _write_step6_manifest_and_step3_contract(self, report: Path) -> None:
        dependencies = report / "evidence" / "dependencies"
        static = report / "evidence" / "static_scan"
        dependencies.mkdir(parents=True, exist_ok=True)
        static.mkdir(parents=True, exist_ok=True)
        (dependencies / "dependency_jars.json").write_text(json.dumps({
            "schema": "java-upgrade-analyzer.step1-dependency-jars.v3",
            "items": [],
            "business_artifacts": [],
            "runtime_closure": {},
        }), encoding="utf-8")
        (static / "s3_database_contract_summary.json").write_text(
            json.dumps({
                "schema": (
                    "java-upgrade-analyzer.database-contract-changes.v1"
                ),
                "coverage_status": "complete",
                "change_count": 0,
                "coverage_gaps": [],
            }),
            encoding="utf-8",
        )
        (static / "s3_database_contract_changes.csv").write_text(
            "依赖包,变化类型,契约类型,可信度,表,列,契约位置,语句或字段,"
            "人工复核建议\n",
            encoding="utf-8",
        )
        (static / "s3_database_contract_changes.md").write_text(
            "# 数据库契约变化明细\n",
            encoding="utf-8",
        )
        coverage = report / ".runtime/coverage/s3_coverage.json"
        coverage.parent.mkdir(parents=True, exist_ok=True)
        coverage.write_text(json.dumps({
            "schema": "java-upgrade-analyzer.step3-coverage.v1",
            "status": "complete",
            "reason_codes": [],
            "planned_scans": [],
            "executed_scans": [],
        }), encoding="utf-8")

    def _activate_sealed(self, output, manifest, validation):
        activation_record = {}
        active_path = Path(activate_binary_generation(
            output,
            manifest,
            validation_result=validation,
            activation_record=activation_record,
        ))
        self.assertTrue(seal_active_binary_generation(
            output,
            expected_current_identity=manifest[
                "result_generation_identity"
            ],
            expected_activation_identity=activation_record[
                "activation_identity"
            ],
        ))
        return active_path

    def _write_test_sealed_active_descriptor(
        self, output, manifest, validation
    ):
        """Write a sealed descriptor for loader-only adversarial fixtures."""

        output = Path(output)
        validation_path = Path(validation["validation_result_path"])
        active = {
            "schema": "java-upgrade-analyzer.active-binary-generation.v1",
            "result_generation_identity": manifest[
                "result_generation_identity"
            ],
            "generation_directory": (
                "binary_generations/"
                f"{manifest['result_generation_identity']}"
            ),
            "validation_run_identity": validation[
                "validation_run_identity"
            ],
            "validation_result_sha256": hashlib.sha256(
                validation_path.read_bytes()
            ).hexdigest(),
        }
        active_path = output / "active_binary_generation.json"
        active_path.write_bytes(binary_output._json_bytes(active))
        return active_path

    def test_sealed_step4_binding_accepts_its_historical_activation_receipt(self):
        loaded = {
            "manifest": {"result_generation_identity": "a" * 64},
            "active": {
                "validation_run_identity": "b" * 64,
                "validation_result_sha256": "c" * 64,
            },
        }
        sealed = binary_report._loaded_step4_publication_binding(loaded)
        historical = {**sealed, "activation_identity": "d" * 64}

        self.assertTrue(
            binary_report._step4_publication_binding_matches_loaded(
                historical, loaded
            )
        )
        loaded["active"]["activation_identity"] = "e" * 64
        self.assertFalse(
            binary_report._step4_publication_binding_matches_loaded(
                historical, loaded
            )
        )

    def test_step5_fact_identity_uses_step4_coord_and_public_symbol_kind(self):
        fact_identity = "f" * 64
        item = {
            "coord": "derived:formal-lineage",
            "target_coord": "derived:formal-lineage",
            "api": "com.acme.Api.<init>",
            "api_signature": "()",
            "symbol_kind": "method",
            "reachability_status": "not_found_in_static_analysis",
            "paths": [],
        }
        change = {
            "coord": "com.acme:public-api",
            "symbol_kind": "constructor",
            "change_type": "REMOVED",
            "change_fact_identity": fact_identity,
            "decision_identity": "d" * 64,
        }

        result = binary_report._legacy_result_item(item, change)

        self.assertEqual(result["coord"], change["coord"])
        self.assertEqual(result["target_coord"], change["coord"])
        self.assertEqual(result["symbol_kind"], change["symbol_kind"])
        self.assertEqual(
            result["api_identity"],
            "|".join((
                change["coord"],
                item["api"],
                item["api_signature"],
                change["symbol_kind"],
                change["change_type"],
                fact_identity,
            )),
        )

    def test_step6_identity_tracks_dynamic_coverage_evidence_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            coverage = report / "evidence/call_chain/coverage.json"
            coverage.parent.mkdir(parents=True)
            coverage.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.coverage.v1",
                "components": [{
                    "id": "custom",
                    "evidence": [
                        "evidence/static_scan/custom.txt",
                        ".runtime/coverage/custom.json",
                    ],
                }],
            }), encoding="utf-8")
            before = binary_report._step6_upstream_evidence_state(
                report, require_complete=False
            )
            custom = report / "evidence/static_scan/custom.txt"
            custom.parent.mkdir(parents=True)
            custom.write_text("first", encoding="utf-8")
            runtime_custom = report / ".runtime/coverage/custom.json"
            runtime_custom.parent.mkdir(parents=True)
            runtime_custom.write_text("{}", encoding="utf-8")
            present = binary_report._step6_upstream_evidence_state(
                report, require_complete=False
            )
            custom.write_text("second", encoding="utf-8")
            changed = binary_report._step6_upstream_evidence_state(
                report, require_complete=False
            )

        self.assertEqual(
            before["evidence/static_scan/custom.txt"]["status"],
            "missing",
        )
        self.assertNotEqual(before, present)
        self.assertNotEqual(present, changed)
        self.assertEqual(
            present[".runtime/coverage/custom.json"]["status"],
            "present",
        )

    def test_step6_upstream_snapshot_copies_only_consumed_regular_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / "report"
            render = root / "render"
            report.mkdir()
            render.mkdir()
            dependencies = report / "evidence/dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "dep_changes.csv").write_text(
                "coord,old_version,new_version,change_type,risk,scope,"
                "resolution_status,base_lib_entry,current_lib_entry\n",
                encoding="utf-8",
            )
            (dependencies / "build_provenance.json").write_text(
                "{}", encoding="utf-8"
            )
            (dependencies / "dependency_jars.json").write_text(
                "{}", encoding="utf-8"
            )
            for excluded in ("s1_artifacts", "s1_dependency_jars"):
                retained = dependencies / excluded / "retained.jar"
                retained.parent.mkdir()
                retained.write_bytes(b"large-retained-runtime-byte-placeholder")
            unapproved = dependencies / "unapproved.txt"
            unapproved.write_text("not consumed", encoding="utf-8")
            context = report / "evidence/context/context.json"
            context.parent.mkdir(parents=True)
            context.write_text("{}", encoding="utf-8")
            custom_scan = report / "evidence/static_scan/custom-evidence.txt"
            custom_scan.parent.mkdir(parents=True)
            custom_scan.write_text("scan evidence", encoding="utf-8")
            custom_coverage = report / ".runtime/coverage/custom.json"
            custom_coverage.parent.mkdir(parents=True)
            custom_coverage.write_text("{}", encoding="utf-8")
            coverage = report / "evidence/call_chain/coverage.json"
            coverage.parent.mkdir(parents=True)
            coverage.write_text(json.dumps({
                "components": [{
                    "id": "bounded",
                    "evidence": [
                        "evidence/static_scan/custom-evidence.txt#row=1",
                        ".runtime/coverage/custom.json",
                        "evidence/dependencies/unapproved.txt",
                        (
                            "evidence/dependencies/s1_dependency_jars/"
                            "retained.jar"
                        ),
                    ],
                }],
            }), encoding="utf-8")
            committed_coverage = (
                render / "evidence/call_chain/coverage.json"
            )
            committed_coverage.parent.mkdir(parents=True)
            committed_coverage.write_bytes(coverage.read_bytes())

            state = binary_report._materialize_step6_upstream_evidence(
                report, render, require_complete=False
            )
            copied = {
                "dep_changes": (
                    render / "evidence/dependencies/dep_changes.csv"
                ).is_file(),
                "dynamic_scan": (
                    render / "evidence/static_scan/custom-evidence.txt"
                ).is_file(),
                "dynamic_coverage": (
                    render / ".runtime/coverage/custom.json"
                ).is_file(),
                "s1_artifacts": (
                    render / "evidence/dependencies/s1_artifacts"
                ).exists(),
                "s1_dependency_jars": (
                    render / "evidence/dependencies/s1_dependency_jars"
                ).exists(),
                "unapproved": (
                    render / "evidence/dependencies/unapproved.txt"
                ).exists(),
            }

        self.assertTrue(copied["dep_changes"])
        self.assertTrue(copied["dynamic_scan"])
        self.assertTrue(copied["dynamic_coverage"])
        self.assertFalse(copied["s1_artifacts"])
        self.assertFalse(copied["s1_dependency_jars"])
        self.assertFalse(copied["unapproved"])
        self.assertNotIn(
            "evidence/dependencies/s1_dependency_jars/retained.jar", state
        )
        self.assertNotIn("evidence/dependencies/unapproved.txt", state)

    def test_step6_snapshot_is_strict_without_orchestration_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / "report"
            render = root / "render"
            report.mkdir()
            render.mkdir()

            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(BinaryReportError) as caught:
                    binary_report._materialize_step6_upstream_evidence(
                        report, render
                    )

        self.assertEqual(caught.exception.owner_step, "step1")
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_UPSTREAM_EVIDENCE_MISSING",
        )

    def test_step6_parent_symlink_fails_without_recovery_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / "report"
            external = root / "external-context"
            report.mkdir()
            external.mkdir()
            context_parent = report / "evidence/context"
            context_parent.parent.mkdir(parents=True)
            try:
                context_parent.symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            (external / "context.json").write_text("{}", encoding="utf-8")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._step6_upstream_evidence_state(
                    report, require_complete=True
                )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
        )
        self.assertTrue(caught.exception.unsafe_parent_path)
        self.assertFalse(hasattr(caught.exception, "owner_step"))

    def test_step6_dynamic_coverage_evidence_must_be_a_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / "report"
            render = root / "render"
            report.mkdir()
            render.mkdir()
            dynamic_directory = report / "evidence/static_scan/directory"
            dynamic_directory.mkdir(parents=True)
            (dynamic_directory / "child.txt").write_text(
                "not directly consumed", encoding="utf-8"
            )
            coverage = report / "evidence/call_chain/coverage.json"
            coverage.parent.mkdir(parents=True)
            coverage.write_text(json.dumps({
                "components": [{
                    "id": "invalid-directory-reference",
                    "evidence": ["evidence/static_scan/directory"],
                }],
            }), encoding="utf-8")
            committed_coverage = (
                render / "evidence/call_chain/coverage.json"
            )
            committed_coverage.parent.mkdir(parents=True)
            committed_coverage.write_bytes(coverage.read_bytes())

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._materialize_step6_upstream_evidence(
                    report, render, require_complete=False
                )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_UPSTREAM_EVIDENCE_PATH_INVALID",
        )

    def test_step6_dynamic_selector_comes_from_committed_step5_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / "report"
            render = root / "render"
            report.mkdir()
            render.mkdir()
            source_only = report / "evidence/static_scan/source-only.txt"
            committed = report / "evidence/static_scan/committed.txt"
            source_only.parent.mkdir(parents=True)
            source_only.write_text("mutable selector", encoding="utf-8")
            committed.write_text("committed selector", encoding="utf-8")
            live_coverage = report / "evidence/call_chain/coverage.json"
            live_coverage.parent.mkdir(parents=True)
            live_coverage.write_text(json.dumps({
                "components": [{
                    "id": "mutated-fixed-path",
                    "evidence": [
                        "evidence/static_scan/source-only.txt"
                    ],
                }],
            }), encoding="utf-8")
            snapshot_coverage = (
                render / "evidence/call_chain/coverage.json"
            )
            snapshot_coverage.parent.mkdir(parents=True)
            snapshot_coverage.write_text(json.dumps({
                "components": [{
                    "id": "committed",
                    "evidence": ["evidence/static_scan/committed.txt"],
                }],
            }), encoding="utf-8")

            state = binary_report._materialize_step6_upstream_evidence(
                report, render, require_complete=False
            )
            copied_committed = (
                render / "evidence/static_scan/committed.txt"
            ).read_text(encoding="utf-8")
            copied_source_only = (
                render / "evidence/static_scan/source-only.txt"
            ).exists()

        self.assertEqual(copied_committed, "committed selector")
        self.assertFalse(copied_source_only)
        self.assertIn("evidence/static_scan/committed.txt", state)
        self.assertNotIn("evidence/static_scan/source-only.txt", state)

    def test_step6_dynamic_selector_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / "report"
            external = root / "external-coverage.json"
            coverage = report / "evidence/call_chain/coverage.json"
            coverage.parent.mkdir(parents=True)
            external.write_text(
                json.dumps({"components": []}), encoding="utf-8"
            )
            try:
                coverage.symlink_to(external)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._step6_upstream_evidence_files(report)

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
        )

    def test_step6_declared_dynamic_evidence_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            dependencies = report / "evidence/dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "dep_changes.csv").write_text(
                "coord,old_version,new_version,change_type,risk,scope,"
                "resolution_status,base_lib_entry,current_lib_entry\n",
                encoding="utf-8",
            )
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.build-provenance.v2",
                    "both_builds_succeeded": True,
                    "sides": [
                        {"side": "base", "artifact_sha256": "a" * 64},
                        {"side": "current", "artifact_sha256": "b" * 64},
                    ],
                }),
                encoding="utf-8",
            )
            self._write_step6_manifest_and_step3_contract(report)
            context = report / "evidence/context/context.json"
            context.parent.mkdir(parents=True)
            context.write_text(json.dumps({
                "build_tool": "maven",
                "base_branch": "base",
                "current_branch": "current",
                "jdk_base": "17",
                "jdk_current": "17",
                "jdk_upgraded": False,
                "springboot_major_upgrade": False,
                "tech_flags": {},
            }), encoding="utf-8")
            static = report / "evidence/static_scan"
            static.mkdir(parents=True, exist_ok=True)
            (static / "s3_dependency_compat.csv").write_text(
                "坐标,版本,风险类型,证据\n", encoding="utf-8"
            )
            (static / "s3_dependency_classfile.csv").write_text(
                "依赖坐标,版本,最高所需Java版本,扫描结论\n",
                encoding="utf-8",
            )
            coverage = report / "evidence/call_chain/coverage.json"
            coverage.parent.mkdir(parents=True)
            missing_relative = "evidence/static_scan/declared.txt"
            referenced_fixed = (
                "evidence/static_scan/s3_jdk_removed_api.csv"
            )
            coverage.write_text(json.dumps({
                "components": [{
                    "evidence": [missing_relative, referenced_fixed]
                }],
            }), encoding="utf-8")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._step6_upstream_evidence_state(
                    report, require_complete=True
                )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_UPSTREAM_EVIDENCE_MISSING",
        )
        self.assertEqual(caught.exception.owner_step, "step3")
        self.assertEqual(
            {
                item["artifact"]
                for item in caught.exception.failure_contract["failures"]
            },
            {missing_relative, referenced_fixed},
        )

    def test_step6_dynamic_coverage_evidence_has_file_size_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            dynamic = report / "evidence/static_scan/custom.txt"
            dynamic.parent.mkdir(parents=True)
            dynamic.write_text("four", encoding="utf-8")
            coverage = report / "evidence/call_chain/coverage.json"
            coverage.parent.mkdir(parents=True)
            coverage.write_text(json.dumps({
                "components": [{
                    "id": "bounded",
                    "evidence": ["evidence/static_scan/custom.txt"],
                }],
            }), encoding="utf-8")

            with patch.object(
                binary_report,
                "_STEP6_DYNAMIC_UPSTREAM_MAX_FILE_BYTES",
                3,
            ):
                with self.assertRaises(BinaryReportError) as caught:
                    binary_report._step6_upstream_evidence_files(report)

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_UPSTREAM_EVIDENCE_BUDGET_EXCEEDED",
        )

    def test_step6_dynamic_coverage_evidence_has_count_and_depth_budgets(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            coverage = report / "evidence/call_chain/coverage.json"
            coverage.parent.mkdir(parents=True)
            coverage.write_text(json.dumps({
                "components": [{
                    "id": "bounded",
                    "evidence": [
                        "evidence/static_scan/one.txt",
                        "evidence/static_scan/two.txt",
                    ],
                }],
            }), encoding="utf-8")

            with patch.object(
                binary_report,
                "_STEP6_DYNAMIC_UPSTREAM_MAX_PATHS",
                1,
            ):
                with self.assertRaises(BinaryReportError) as count_error:
                    binary_report._step6_upstream_evidence_files(report)
            coverage.write_text(json.dumps({
                "components": [{
                    "id": "too-deep",
                    "evidence": [
                        "evidence/static_scan/a/b/c/d/e.txt"
                    ],
                }],
            }), encoding="utf-8")
            with self.assertRaises(BinaryReportError) as depth_error:
                binary_report._step6_upstream_evidence_files(report)

        self.assertEqual(
            count_error.exception.reason_code,
            "BINARY_STEP6_UPSTREAM_EVIDENCE_BUDGET_EXCEEDED",
        )
        self.assertEqual(
            depth_error.exception.reason_code,
            "BINARY_STEP6_UPSTREAM_EVIDENCE_PATH_INVALID",
        )

    def test_step6_internal_input_failure_owner_is_earliest_analyzer_step(self):
        findings = {"diagnostics": [
            {
                "artifact": "step3_database_contract_changes",
                "stage": "cross_artifact_contract",
                "error_type": "ValueError",
            },
            {
                "artifact": "context",
                "stage": "json_contract",
                "error_type": "ArtifactContentError",
            },
            {
                "artifact": "dependency_changes",
                "stage": "csv_contract",
                "error_type": "ArtifactContentError",
            },
            {
                "artifact": "coverage",
                "stage": "coverage_limitation",
                "error_type": "CoverageGap",
            },
        ]}

        contract = binary_report.step6_internal_input_failure_contract(
            findings
        )

        self.assertEqual(
            binary_report.step6_internal_input_failure_owner(findings),
            "step1",
        )
        self.assertEqual(contract["owner_step"], "step1")
        self.assertEqual(
            [item["owner_step"] for item in contract["failures"]],
            ["step1", "step2", "step3"],
        )

    def test_step6_publication_findings_fail_closed_on_step1_csv_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            dependency_changes = (
                report / "evidence/dependencies/dep_changes.csv"
            )
            dependency_changes.parent.mkdir(parents=True)
            dependency_changes.write_text(
                "coord,change_type\ncom.acme:api,升级\n",
                encoding="utf-8",
            )

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._collect_step6_findings_for_publication(report)

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_INTERNAL_INPUT_INVALID",
        )
        self.assertEqual(caught.exception.owner_step, "step1")
        self.assertEqual(
            caught.exception.failure_contract["schema"],
            "java-upgrade-analyzer.step6-internal-input-failure.v1",
        )

    def test_step6_publication_findings_fail_closed_on_step3_csv_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            scan = report / "evidence/static_scan/s3_dependency_compat.csv"
            scan.parent.mkdir(parents=True)
            scan.write_text("forged\nvalue\n", encoding="utf-8")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._collect_step6_findings_for_publication(report)

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_INTERNAL_INPUT_INVALID",
        )
        self.assertEqual(caught.exception.owner_step, "step3")

    def test_step6_required_malformed_context_reports_step2_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            dependencies = report / "evidence/dependencies"
            dependencies.mkdir(parents=True)
            (dependencies / "dep_changes.csv").write_text(
                "coord,old_version,new_version,change_type,risk,scope,"
                "resolution_status,base_lib_entry,current_lib_entry\n",
                encoding="utf-8",
            )
            (dependencies / "build_provenance.json").write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.build-provenance.v2",
                    "both_builds_succeeded": True,
                    "sides": [
                        {"side": "base", "artifact_sha256": "a" * 64},
                        {"side": "current", "artifact_sha256": "b" * 64},
                    ],
                }),
                encoding="utf-8",
            )
            self._write_step6_manifest_and_step3_contract(report)
            context = report / "evidence/context/context.json"
            context.parent.mkdir(parents=True)
            context.write_text("{not-json", encoding="utf-8")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._step6_upstream_evidence_state(
                    report, require_complete=True
                )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_INTERNAL_INPUT_INVALID",
        )
        self.assertEqual(caught.exception.owner_step, "step2")

    def test_step6_missing_inputs_choose_earliest_producer(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            context = report / "evidence/context/context.json"
            context.parent.mkdir(parents=True)
            context.write_text("{not-json", encoding="utf-8")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._step6_upstream_evidence_state(
                    report, require_complete=True
                )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_INTERNAL_INPUT_INVALID",
        )
        self.assertEqual(caught.exception.owner_step, "step1")
        self.assertEqual(
            sorted({
                item["owner_step"]
                for item in caught.exception.failure_contract["failures"]
            }),
            ["step1", "step2", "step3"],
        )

    def test_step6_empty_context_contract_reports_step2_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            context = report / "evidence/context/context.json"
            context.parent.mkdir(parents=True)
            context.write_text("{}", encoding="utf-8")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._collect_step6_findings_for_publication(report)

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_INTERNAL_INPUT_INVALID",
        )
        self.assertEqual(caught.exception.owner_step, "step2")

    def test_step6_empty_build_provenance_sides_report_step1_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            provenance = (
                report / "evidence/dependencies/build_provenance.json"
            )
            provenance.parent.mkdir(parents=True)
            provenance.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.build-provenance.v2",
                "both_builds_succeeded": True,
                "sides": [],
            }), encoding="utf-8")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._collect_step6_findings_for_publication(report)

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_STEP6_INTERNAL_INPUT_INVALID",
        )
        self.assertEqual(caught.exception.owner_step, "step1")

    def test_step6_partial_step3_coverage_is_a_valid_internal_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve()
            coverage = report / ".runtime/coverage/s3_coverage.json"
            coverage.parent.mkdir(parents=True)
            coverage.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.step3-coverage.v1",
                "status": "partial",
                "reason_codes": ["source_file_read_failures"],
                "planned_scans": ["jdk_removed"],
                "executed_scans": ["jdk_removed"],
            }), encoding="utf-8")
            findings = {"diagnostics": []}

            binary_report._augment_step6_internal_input_diagnostics(
                report, findings
            )

        self.assertEqual(findings["diagnostics"], [])
        self.assertIsNone(
            binary_report.step6_internal_input_failure_owner(findings)
        )

    def test_binary_report_cli_persists_step6_failure_owner_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            result_path = root / "failure.json"
            failure_contract = {
                "schema": (
                    "java-upgrade-analyzer.step6-internal-input-failure.v1"
                ),
                "status": "failed",
                "owner_step": "step2",
                "failures": [],
            }
            failure = BinaryReportError(
                "BINARY_STEP6_INTERNAL_INPUT_INVALID",
                "invalid Step2 context",
            )
            failure.owner_step = "step2"
            failure.failure_contract = failure_contract

            with patch.object(
                binary_report, "publish_step6", side_effect=failure
            ), patch.object(sys, "stderr", io.StringIO()):
                with self.assertRaises(BinaryReportError):
                    binary_report.main([
                        "--phase", "step6",
                        "--report-dir", str(root),
                        "--output-findings", str(root / "findings.json"),
                        "--output-report", str(root / "report.md"),
                        "--result-json", str(result_path),
                    ])
            result = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason_code"], (
            "BINARY_STEP6_INTERNAL_INPUT_INVALID"
        ))
        self.assertEqual(result["owner_step"], "step2")
        self.assertEqual(result["failure_contract"], failure_contract)

    def test_step6_coverage_limitation_is_not_an_internal_input_failure(self):
        findings = {"diagnostics": [{
            "artifact": "coverage",
            "stage": "json_contract",
            "error_type": "ArtifactContentError",
            "message": "coverage is partial",
        }]}

        self.assertIsNone(
            binary_report.step6_internal_input_failure_owner(findings)
        )
        self.assertEqual(
            binary_report.step6_internal_input_failure_contract(findings)[
                "status"
            ],
            "passed",
        )

    def test_report_publication_rejects_symlink_destination_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "outside"
            target.mkdir()
            marker = target / "marker"
            marker.write_text("untouched", encoding="utf-8")
            destination = root / "api_changes"
            try:
                destination.symlink_to(target, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._stage_directory(
                    destination,
                    lambda stage: (stage / "marker").write_text(
                        "modified", encoding="utf-8"
                    ),
                )

            target_value = marker.read_text(encoding="utf-8")

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
        )
        self.assertEqual(target_value, "untouched")

    def test_report_publication_rejects_symlinked_parent_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            outside = root / "outside"
            outside.mkdir()
            marker = outside / "marker"
            marker.write_text("untouched", encoding="utf-8")
            linked_parent = root / "linked-evidence"
            try:
                linked_parent.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._stage_directory(
                    linked_parent / "api_changes",
                    lambda stage: (stage / "marker").write_text(
                        "modified", encoding="utf-8"
                    ),
                )

            target_value = marker.read_text(encoding="utf-8")

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
        )
        self.assertEqual(target_value, "untouched")

    def test_report_publication_does_not_create_missing_directories_below_ancestor_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel.txt"
            sentinel.write_text("untouched", encoding="utf-8")
            linked_parent = root / "linked-evidence"
            try:
                linked_parent.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._stage_directory(
                    linked_parent / "new-parent" / "api_changes",
                    lambda stage: (stage / "marker").write_text(
                        "modified", encoding="utf-8"
                    ),
                )

            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
            )
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")
            self.assertFalse((outside / "new-parent").exists())

    def test_report_publication_allows_symlink_ancestor_above_trusted_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            physical_parent = root / "physical-parent"
            report = physical_parent / "report"
            report.mkdir(parents=True)
            linked_parent = root / "linked-parent"
            try:
                linked_parent.symlink_to(
                    physical_parent, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")
            requested_report = linked_parent / "report"
            destination = (
                requested_report / "evidence" / "api_changes"
            )

            binary_report._stage_directory_group(
                ((
                    destination,
                    lambda stage, _prepared: (
                        stage / "marker.txt"
                    ).write_text("published", encoding="utf-8"),
                ),),
                trusted_root=requested_report,
            )

            self.assertEqual(
                (
                    report / "evidence" / "api_changes" / "marker.txt"
                ).read_text(encoding="utf-8"),
                "published",
            )

    def test_report_publication_rejects_symlink_transaction_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            destination = root / "api_changes"
            destination.mkdir()
            (destination / "marker").write_text("old", encoding="utf-8")
            normalized = binary_report._normalize_publication_destination(
                destination
            )
            transaction_path, _token = (
                binary_report._publication_transaction_path([normalized])
            )
            external = root / "external-transaction.json"
            external.write_text("external", encoding="utf-8")
            try:
                transaction_path.symlink_to(external)
            except OSError as error:
                self.skipTest(f"file symlinks unavailable: {error}")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report._stage_directory(
                    destination,
                    lambda stage: (stage / "marker").write_text(
                        "new", encoding="utf-8"
                    ),
                )

            external_value = external.read_text(encoding="utf-8")
            destination_value = (destination / "marker").read_text(
                encoding="utf-8"
            )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
        )
        self.assertEqual(external_value, "external")
        self.assertEqual(destination_value, "old")

    def test_report_transaction_read_rejects_regular_to_fifo_open_race(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            destination = root / "api_changes"
            destination.mkdir()
            (destination / "marker").write_text("old", encoding="utf-8")
            binary_report._stage_directory_group((
                (destination, lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new", encoding="utf-8")),
            ), retain_transaction=True)
            normalized = binary_report._normalize_publication_destination(
                destination
            )
            transaction_path, _token = (
                binary_report._publication_transaction_path([normalized])
            )
            saved_marker = root / "saved-transaction.json"
            fifo = root / "replacement-fifo"
            try:
                os.mkfifo(fifo)
            except OSError as error:
                self.skipTest(f"FIFO is unavailable: {error}")
            real_open = os.open
            swapped = False

            def replace_before_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if Path(path) == transaction_path and not swapped:
                    swapped = True
                    os.replace(transaction_path, saved_marker)
                    os.replace(fifo, transaction_path)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(binary_report.os, "open", replace_before_open):
                with self.assertRaises(BinaryReportError) as caught:
                    binary_report.report_publication_transaction_state(
                        (destination,)
                    )

            self.assertTrue(saved_marker.is_file())

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
        )

    def test_process_lock_rejects_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "target"
            target.write_bytes(b"")
            lock = root / "state.lock"
            try:
                lock.symlink_to(target)
            except OSError as error:
                self.skipTest(f"file symlinks unavailable: {error}")

            with self.assertRaises(OSError):
                with exclusive_file_lock(lock, timeout_seconds=0.01):
                    self.fail("symlink lock unexpectedly acquired")

            target_bytes = target.read_bytes()

        self.assertEqual(target_bytes, b"")

    def test_process_lock_rejects_hardlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            target = root / "target"
            target.write_bytes(b"original")
            lock = root / "state.lock"
            try:
                os.link(target, lock)
            except OSError as error:
                self.skipTest(f"hardlinks unavailable: {error}")

            with self.assertRaises(OSError):
                with exclusive_file_lock(lock, timeout_seconds=0.01):
                    self.fail("hardlink lock unexpectedly acquired")

            target_bytes = target.read_bytes()

        self.assertEqual(target_bytes, b"original")

    def test_process_lock_closes_descriptor_when_explicit_unlock_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp).resolve() / "state.lock"
            descriptors = []
            real_open = process_lock._open_validated_lock_file

            def capture_descriptor(path):
                descriptor = real_open(path)
                descriptors.append(descriptor)
                return descriptor

            with patch.object(
                process_lock,
                "_open_validated_lock_file",
                side_effect=capture_descriptor,
            ), patch.object(
                process_lock,
                "_unlock",
                side_effect=OSError("injected unlock failure"),
            ):
                with self.assertRaisesRegex(OSError, "injected unlock failure"):
                    with exclusive_file_lock(lock, timeout_seconds=0.1):
                        pass

            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])
            # Closing the failed descriptor must have released the OS lock,
            # so a later Step4/report activation can acquire it normally.
            with exclusive_file_lock(lock, timeout_seconds=0.1):
                self.assertTrue(lock.is_file())

    def test_process_lock_preserves_body_failure_and_attempts_all_cleanup(self):
        primary = RuntimeError("body primary")
        unlock = Mock(side_effect=OSError("unlock cleanup"))
        real_close = os.close

        def close_then_fail(descriptor):
            real_close(descriptor)
            raise OSError("close cleanup")

        close = Mock(side_effect=close_then_fail)
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "state.lock"
            with patch.object(
                process_lock, "_unlock", unlock
            ), patch.object(
                process_lock.os, "close", close
            ):
                with self.assertRaises(RuntimeError) as caught:
                    with exclusive_file_lock(lock, timeout_seconds=0.1):
                        raise primary

        self.assertIs(caught.exception, primary)
        unlock.assert_called_once()
        close.assert_called_once()
        notes = list(getattr(primary, "__notes__", ()))
        self.assertTrue(any("unlock cleanup" in note for note in notes))
        self.assertTrue(any("close cleanup" in note for note in notes))

    def test_active_descriptor_cleanup_does_not_replace_publish_failure(self):
        primary = RuntimeError("active publish primary")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with patch.object(
                binary_output.os, "replace", side_effect=primary
            ), patch.object(
                binary_output,
                "_unlink_missing_ok",
                side_effect=OSError("active cleanup"),
            ):
                with self.assertRaises(RuntimeError) as caught:
                    binary_output._write_active_descriptor(
                        root, {"schema": "test"}, expect_missing=True
                    )

        self.assertIs(caught.exception, primary)
        self.assertTrue(any(
            "active cleanup" in note
            for note in getattr(primary, "__notes__", ())
        ))

    def test_report_atomic_cleanup_does_not_replace_publish_failure(self):
        primary = RuntimeError("report publish primary")
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "report.json"
            with patch.object(
                binary_report.os, "replace", side_effect=primary
            ), patch.object(
                binary_report,
                "_unlink_missing_ok",
                side_effect=OSError("report cleanup"),
            ):
                with self.assertRaises(RuntimeError) as caught:
                    binary_report._atomic_json(destination, {"value": 1})

        self.assertIs(caught.exception, primary)
        self.assertTrue(any(
            "report cleanup" in note
            for note in getattr(primary, "__notes__", ())
        ))

    def test_report_publication_lock_cleanup_preserves_writer_failure(self):
        primary = RuntimeError("report writer primary")
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp).resolve() / "api_changes"
            with patch.object(
                process_lock,
                "_unlock",
                side_effect=OSError("report unlock cleanup"),
            ):
                with self.assertRaises(RuntimeError) as caught:
                    binary_report._stage_directory(
                        destination,
                        lambda _stage: (_ for _ in ()).throw(primary),
                    )

        self.assertIs(caught.exception, primary)
        self.assertTrue(any(
            "report unlock cleanup" in note
            for note in getattr(primary, "__notes__", ())
        ))

    def test_report_durability_does_not_ignore_file_fsync_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_file = Path(tmp) / "report.json"
            report_file.write_text("{}\n", encoding="utf-8")
            with patch.object(
                binary_report.os,
                "fsync",
                side_effect=OSError("report media failure"),
            ):
                with self.assertRaises(BinaryReportError) as caught:
                    binary_report._report_file_sha256(
                        report_file, make_durable=True
                    )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID",
        )
        self.assertIn("report media failure", str(caught.exception))

    def test_grouped_report_publication_recovers_process_death_between_swaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            first = root / "api_changes"
            second = root / "source_analysis"
            first.mkdir()
            second.mkdir()
            (first / "marker").write_text("old-api", encoding="utf-8")
            (second / "marker").write_text("old-source", encoding="utf-8")
            script = r'''
import os
import sys
from pathlib import Path
import binary_report

first = Path(sys.argv[1]).resolve()
second = Path(sys.argv[2]).resolve()
real_replace = os.replace

def crash_after_first_install(source, destination):
    real_replace(source, destination)
    if Path(destination) == first and str(source).endswith(".stage"):
        os._exit(91)

binary_report.os.replace = crash_after_first_install
binary_report._stage_directory_group((
    (first, lambda stage, _prepared: (stage / "marker").write_text(
        "crash-api", encoding="utf-8"
    )),
    (second, lambda stage, _prepared: (stage / "marker").write_text(
        "crash-source", encoding="utf-8"
    )),
))
'''
            environment = dict(os.environ)
            environment["PYTHONPATH"] = os.pathsep.join(filter(None, (
                str(ROOT_DIR / "scripts"), environment.get("PYTHONPATH", "")
            )))
            crashed = subprocess.run(
                [sys.executable, "-c", script, str(first), str(second)],
                cwd=ROOT_DIR,
                env=environment,
                check=False,
            )
            self.assertEqual(crashed.returncode, 91)
            self.assertEqual(
                (first / "marker").read_text(encoding="utf-8"), "crash-api"
            )
            self.assertEqual(
                (second / "marker").read_text(encoding="utf-8"), "old-source"
            )
            self.assertEqual(
                len(list(root.glob(".jua-br-*.transaction.json"))), 1
            )

            observed_after_recovery = []

            def write_first(stage, _prepared):
                (stage / "marker").write_text("final-api", encoding="utf-8")

            def write_second(stage, _prepared):
                observed_after_recovery.append((
                    (first / "marker").read_text(encoding="utf-8"),
                    (second / "marker").read_text(encoding="utf-8"),
                ))
                (stage / "marker").write_text("final-source", encoding="utf-8")

            binary_report._stage_directory_group((
                (second, write_second),
                (first, write_first),
            ))
            final_values = (
                (first / "marker").read_text(encoding="utf-8"),
                (second / "marker").read_text(encoding="utf-8"),
            )
            remaining_transactions = list(
                root.glob(".jua-br-*.transaction.json")
            )
            remaining_backups = list(root.glob(".jua-br-*.backup"))
            remaining_stages = list(root.glob(".jua-br-*.stage"))

        self.assertEqual(observed_after_recovery, [("old-api", "old-source")])
        self.assertEqual(final_values, ("final-api", "final-source"))
        self.assertFalse(remaining_transactions)
        self.assertFalse(remaining_backups)
        self.assertFalse(remaining_stages)

    def test_grouped_report_publication_restores_every_destination_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            first = root / "api_changes"
            second = root / "source_analysis"
            first.mkdir()
            second.mkdir()
            (first / "marker").write_text("old-api", encoding="utf-8")
            (second / "marker").write_text("old-source", encoding="utf-8")

            def write_first(stage, _prepared):
                (stage / "marker").write_text("new-api", encoding="utf-8")

            def fail_second(stage, _prepared):
                (stage / "marker").write_text("new-source", encoding="utf-8")
                raise OSError("injected source report failure")

            with self.assertRaisesRegex(OSError, "injected source"):
                binary_report._stage_directory_group((
                    (first, write_first),
                    (second, fail_second),
                ))

            first_value = (first / "marker").read_text(encoding="utf-8")
            second_value = (second / "marker").read_text(encoding="utf-8")

        self.assertEqual(first_value, "old-api")
        self.assertEqual(second_value, "old-source")

    def test_pending_gate_publication_can_rollback_or_commit_both_views(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            first = root / "api_changes"
            second = root / "source_analysis"
            for destination, value in (
                (first, "old-api"), (second, "old-source")
            ):
                destination.mkdir()
                (destination / "marker").write_text(value, encoding="utf-8")

            def publish(api_value, source_value):
                return binary_report._stage_directory_group((
                    (first, lambda stage, _prepared: (
                        stage / "marker"
                    ).write_text(api_value, encoding="utf-8")),
                    (second, lambda stage, _prepared: (
                        stage / "marker"
                    ).write_text(source_value, encoding="utf-8")),
                ), retain_transaction=True)

            pending = publish("rollback-api", "rollback-source")
            self.assertEqual(pending["state"], "pending_gate")
            self.assertEqual(
                (
                    (first / "marker").read_text(encoding="utf-8"),
                    (second / "marker").read_text(encoding="utf-8"),
                ),
                ("old-api", "old-source"),
            )
            self.assertEqual(
                binary_report.report_publication_transaction_state(
                    (first, second)
                ),
                "pending_gate",
            )
            self.assertTrue(binary_report.rollback_report_publication(
                (first, second),
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
            ))
            rolled_back = (
                (first / "marker").read_text(encoding="utf-8"),
                (second / "marker").read_text(encoding="utf-8"),
            )

            pending = publish("commit-api", "commit-source")
            self.assertTrue(binary_report.mark_report_publication_gate_passed(
                (first, second),
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
                gate_name="test_gate",
                strict_risk_gate=False,
            ))
            self.assertTrue(binary_report.publish_report_publication(
                (first, second),
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
            ))
            self.assertTrue(binary_report.commit_report_publication(
                (first, second),
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
            ))
            committed = (
                (first / "marker").read_text(encoding="utf-8"),
                (second / "marker").read_text(encoding="utf-8"),
            )
            final_state = binary_report.report_publication_transaction_state(
                (first, second)
            )
            committed_receipt = (
                binary_report.report_publication_committed_receipt(
                    (first, second),
                    expected_transaction_id=pending["transaction_id"],
                    expected_binding=pending["binding"],
                )
            )

        self.assertEqual(rolled_back, ("old-api", "old-source"))
        self.assertEqual(committed, ("commit-api", "commit-source"))
        self.assertEqual(final_state, "absent")
        self.assertEqual(committed_receipt["state"], "committed")
        self.assertEqual(
            committed_receipt["gate_receipt"]["gate_name"], "test_gate"
        )
        self.assertFalse(
            committed_receipt["gate_receipt"]["strict_risk_gate"]
        )

    def test_gate_passed_publication_resumes_each_durable_rename_window(self):
        for crash_point in (
            "after_first_backup",
            "after_first_install",
            "after_all_installs",
        ):
            with self.subTest(crash_point=crash_point), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                destinations = (root / "api_changes", root / "source_analysis")
                for destination, value in zip(
                    destinations, ("old-api", "old-source")
                ):
                    destination.mkdir()
                    (destination / "marker").write_text(value, encoding="utf-8")
                pending = binary_report._stage_directory_group((
                    (destinations[0], lambda stage, _prepared: (
                        stage / "marker"
                    ).write_text("new-api", encoding="utf-8")),
                    (destinations[1], lambda stage, _prepared: (
                        stage / "marker"
                    ).write_text("new-source", encoding="utf-8")),
                ), retain_transaction=True)
                binary_report.mark_report_publication_gate_passed(
                    destinations,
                    expected_transaction_id=pending["transaction_id"],
                    expected_binding=pending["binding"],
                    gate_name="test_gate",
                    strict_risk_gate=False,
                )
                transaction_path = Path(pending["transaction_path"])
                payload = json.loads(transaction_path.read_text(encoding="utf-8"))
                first = payload["destinations"][0]
                if crash_point in {"after_first_backup", "after_first_install", "after_all_installs"}:
                    os.replace(first["destination"], first["backup"])
                if crash_point in {"after_first_install", "after_all_installs"}:
                    os.replace(first["stage"], first["destination"])
                if crash_point == "after_all_installs":
                    second = payload["destinations"][1]
                    os.replace(second["destination"], second["backup"])
                    os.replace(second["stage"], second["destination"])

                self.assertTrue(binary_report.publish_report_publication(
                    destinations,
                    expected_transaction_id=pending["transaction_id"],
                    expected_binding=pending["binding"],
                ))
                values = tuple(
                    (destination / "marker").read_text(encoding="utf-8")
                    for destination in destinations
                )

            self.assertEqual(values, ("new-api", "new-source"))

    def test_committed_reader_snapshot_is_receipt_bound_and_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            destinations = (root / "api_changes", root / "source_analysis")
            pending = binary_report._stage_directory_group((
                (destinations[0], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("generation-a-api", encoding="utf-8")),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("generation-a-source", encoding="utf-8")),
            ), retain_transaction=True)
            binary_report.mark_report_publication_gate_passed(
                destinations,
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
                gate_name="test_gate",
                strict_risk_gate=False,
            )
            binary_report.publish_report_publication(
                destinations,
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
            )
            self.assertTrue(binary_report.commit_report_publication(
                destinations,
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
            ))
            snapshot_root = root / "reader-snapshot"
            snapshot_root.mkdir()
            snapshot = (
                binary_report.materialize_report_publication_committed_snapshot(
                    destinations,
                    snapshot_root,
                    expected_transaction_id=pending["transaction_id"],
                    expected_binding=pending["binding"],
                )
            )
            snapshot_paths = [
                Path(item) for item in snapshot["snapshot_destinations"]
            ]

            binary_report._stage_directory_group((
                (destinations[0], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("generation-b-api", encoding="utf-8")),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("generation-b-source", encoding="utf-8")),
            ))
            fixed_values = tuple(
                (destination / "marker").read_text(encoding="utf-8")
                for destination in destinations
            )
            snapshot_values = tuple(
                (destination / "marker").read_text(encoding="utf-8")
                for destination in snapshot_paths
            )

        self.assertEqual(
            fixed_values, ("generation-b-api", "generation-b-source")
        )
        self.assertEqual(
            snapshot_values, ("generation-a-api", "generation-a-source")
        )
        self.assertEqual(snapshot["transaction_id"], pending["transaction_id"])

    def test_committed_reader_snapshot_rejects_tampered_public_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            destination = root / "api_changes"
            pending = binary_report._stage_directory_group((
                (destination, lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("committed", encoding="utf-8")),
            ), retain_transaction=True)
            binary_report.mark_report_publication_gate_passed(
                (destination,),
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
                gate_name="test_gate",
                strict_risk_gate=False,
            )
            binary_report.publish_report_publication(
                (destination,),
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
            )
            self.assertTrue(binary_report.commit_report_publication(
                (destination,),
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
            ))
            (destination / "marker").write_text("tampered", encoding="utf-8")
            snapshot_root = root / "reader-snapshot"
            snapshot_root.mkdir()

            with self.assertRaises(BinaryReportError) as caught:
                binary_report.materialize_report_publication_committed_snapshot(
                    (destination,), snapshot_root
                )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
        )

    def test_immediate_publication_cleanup_failure_preserves_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp).resolve() / "published"
            with patch.object(
                binary_report,
                "_finish_committed_publication",
                return_value=False,
            ):
                result = binary_report._stage_directory_group((
                    (destination, lambda stage, _prepared: (
                        stage / "marker"
                    ).write_text("new", encoding="utf-8")),
                ))

            self.assertIsNone(result)
            self.assertEqual(
                (destination / "marker").read_text(encoding="utf-8"),
                "new",
            )

    def test_report_publication_content_tampering_fails_closed_before_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            first = root / "api_changes"
            second = root / "source_analysis"
            for destination, value in (
                (first, "old-api"), (second, "old-source")
            ):
                destination.mkdir()
                (destination / "marker").write_text(value, encoding="utf-8")
            pending = binary_report._stage_directory_group((
                (first, lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new-api", encoding="utf-8")),
                (second, lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new-source", encoding="utf-8")),
            ), retain_transaction=True)
            candidate = Path(pending["candidate_destinations"][0])
            (candidate / "marker").write_text("tampered", encoding="utf-8")

            with self.assertRaises(BinaryReportError) as caught:
                binary_report.mark_report_publication_gate_passed(
                    (first, second),
                    expected_transaction_id=pending["transaction_id"],
                    expected_binding=pending["binding"],
                    gate_name="test_gate",
                    strict_risk_gate=False,
                )
            state = binary_report.report_publication_transaction_state(
                (first, second)
            )
            self.assertTrue(binary_report.rollback_report_publication(
                (first, second),
                expected_transaction_id=pending["transaction_id"],
                expected_binding=pending["binding"],
            ))
            restored = (
                (first / "marker").read_text(encoding="utf-8"),
                (second / "marker").read_text(encoding="utf-8"),
            )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
        )
        self.assertEqual(state, "pending_gate")
        self.assertEqual(restored, ("old-api", "old-source"))

    def test_report_directory_publication_serializes_concurrent_writers(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp).resolve() / "published"
            destination.mkdir()
            (destination / "marker").write_text("old", encoding="utf-8")

            def publish(label):
                binary_report._stage_directory(
                    destination,
                    lambda stage: (stage / "marker").write_text(
                        label, encoding="utf-8"
                    ),
                )
                return label

            with ThreadPoolExecutor(max_workers=2) as executor:
                completed = list(executor.map(publish, ("A", "B")))
            final_value = (destination / "marker").read_text(encoding="utf-8")

        self.assertEqual(completed, ["A", "B"])
        self.assertIn(final_value, {"A", "B"})

    def test_generation_identity_requires_every_core_sidecar_declaration(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )

        self.assertEqual(
            _result_generation_identity_from_manifest(manifest),
            manifest["result_generation_identity"],
        )
        incomplete = dict(manifest)
        incomplete["sidecar_content_identities"] = dict(
            manifest["sidecar_content_identities"]
        )
        incomplete["sidecar_content_identities"].pop("binary_summary.json")
        self.assertEqual(
            _result_generation_identity_from_manifest(incomplete), ""
        )

    def test_jvm_descriptor_is_presented_as_java_parameter_signature(self):
        self.assertEqual(jvm_method_parameter_signature("()I"), "()")
        self.assertEqual(
            jvm_method_parameter_signature("(Ljava/lang/String;[I[[Lcom/acme/Dto;)V"),
            "(java.lang.String,int[],com.acme.Dto[][])",
        )
        with self.assertRaisesRegex(ValueError, "invalid_method_descriptor"):
            jvm_method_parameter_signature("(I")

    def profile(self):
        required = RuntimeProfile.REQUIRED_FIELDS
        return RuntimeProfile({
            "target_jvm": {"vendor": "test", "major": 21},
            "runtime_platform_image_identity": "platform-1",
            "target_os": "linux",
            "target_arch": "amd64",
            "container_and_launcher_kind": "java-classpath",
            "ordered_runtime_path_entry_descriptors": [{
                "logical_location": "lib/api.jar", "content_sha256": "a" * 64,
                "path_kind": "classpath", "slot": 0, "loader_realm": "app",
            }],
            "loader_topology": {"app": {"parent": "platform"}},
            "runtime_code_source_origin_mapping_identity": "origins-1",
            "runtime_security_and_package_sealing_policy_identity": "security-1",
            "active_profile_identities": ["default"],
            "external_config_snapshot_identities": [],
            "agent_transformer_plugin_profile_identities": [],
            "business_entrypoint_profile": {"coverage_status": "complete", "methods": []},
            "runtime_class_closure_coverage_status": "complete",
            "resource_selection_coverage_status": "complete",
            "field_coverage": {key: "known" for key in required},
        })

    def bundles(self):
        context = "context-1"
        decision = {
            "observed_delta_identity": "observed-1",
            "disposition_obligation_identity": "obligation-1",
            "decision_identity": "decision-1",
            "decision_channel": "authoritative",
            "change_fact_identity": "change-1",
            "change_fact_status": "confirmed",
            "fact_kind": "method",
            "fact_scope": {
                "initiating_loader_realm_identity": "app",
                "class_name": "vendor/Api",
                "member_kind": "method",
                "member_name": "work",
                "descriptor": "()V",
            },
            "coverage_gaps": [],
        }
        assessment = {
            "projection_assessment_identity": "assessment-1",
            "decision_identity": "decision-1",
            "change_fact_identity": "change-1",
            "analysis_projection_status": "targetable",
            "projection_coverage_status": "complete",
            "target_identities": ["target-1"],
            "projection_obligation_keys": ["obligation-key-1"],
            "partial_projection_scopes": [],
        }
        projection = {
            "projection_identity": "projection-1",
            "projection_assessment_identity": "assessment-1",
            "projection_obligation_key": "obligation-key-1",
            "change_fact_identity": "change-1",
            "target_identity": "target-1",
        }
        snapshots = {
            "decision": ActiveSnapshot("decision", context, ("decision-1",)),
            "assessment": ActiveSnapshot("assessment", context, ("assessment-1",)),
            "formal_projection": ActiveSnapshot("formal_projection", context, ("projection-1",)),
            "candidate_projection": ActiveSnapshot("candidate_projection", context, ()),
        }
        decisions = BinaryDecisionBundle(
            context,
            (decision,),
            (),
            (),
            (assessment,),
            (projection,),
            (),
            snapshots,
            "complete",
            (),
            "decision-bundle-1",
        )
        formal = {
            "projection_identity": "projection-1",
            "decision_identity": "decision-1",
            "change_fact_identity": "change-1",
            "projection_assessment_identity": "assessment-1",
            "analysis_context_identity": context,
            "trace_result_identity": "trace-1",
            "reachability_status": "reachable",
            "analysis_status": "reachable",
            "is_reachable": True,
            "impact_conclusion": "probable_impact",
            "runtime_verification_status": "required_not_executed",
            "runtime_verification_executed_by_system": False,
            "path_set_complete": True,
            "exact_path_exists": True,
            "possible_path_exists": False,
        }
        traces = BinaryTraceBundle(
            context,
            (formal,),
            (),
            "trace-set-1",
            "complete",
            (),
            "trace-bundle-1",
        )
        return decisions, traces

    def expected_validator_implementation_identity(self):
        expected_source_paths = (
            "artifact_safety.py",
            "binary_first_contract.py",
            "binary_tool_execution.py",
            "binary_validation_contract.py",
            "binary_validation_oracle.py",
            "compat.py",
            "edge_truth.py",
            "final_artifact_edge_oracle.py",
            "jdk_preflight.py",
            "javap_contract.py",
            "java/RuntimeOutcomeOracle.java",
            "path_runtime.py",
            "streaming_json.py",
        )
        implementation_sources = [
            {
                "path": relative,
                "sha256": hashlib.sha256(
                    (ROOT_DIR / "scripts" / relative).read_bytes()
                ).hexdigest(),
            }
            for relative in expected_source_paths
        ]
        return canonical_identity(
            "binary_validation_implementation_identity",
            {
                "policy_version": "binary-independent-validation-v3",
                "implementation_sources": implementation_sources,
                "python_runtime": {
                    "implementation": str(sys.implementation.name),
                    "cache_tag": str(sys.implementation.cache_tag or ""),
                    "version": [
                        int(sys.version_info.major),
                        int(sys.version_info.minor),
                        int(sys.version_info.micro),
                    ],
                    "platform": str(sys.platform),
                    "sqlite_version": str(sqlite3.sqlite_version),
                    "zlib_runtime_version": str(zlib.ZLIB_RUNTIME_VERSION),
                },
            },
            schema_version="1",
        )

    def validation_result(self, manifest, **overrides):
        support = json.loads(
            (ROOT_DIR / "scripts" / "binary_first_support_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        support_identity = canonical_identity(
            "oracle_support_manifest_identity",
            support["oracle_support_manifest"],
            schema_version="1",
        )
        policy_version = "binary-independent-validation-v3"
        implementation_identity = (
            self.expected_validator_implementation_identity()
        )
        result = {
            "schema": "java-upgrade-analyzer.binary-validation-result.v1",
            "result_generation_identity": manifest["result_generation_identity"],
            "oracle_support_manifest_identity": support_identity,
            "truth_set_identity": "d" * 64,
            "validation_policy_version": policy_version,
            "validator_implementation_identity": implementation_identity,
            "status": "passed",
            "issue_count": 0,
            "issues": [],
            "domain_summary": {},
            "helper_identities": {"base": "e" * 64, "current": "f" * 64},
            "skipped_domains": [],
            "production_identity_influence": "none_validation_attachment_only",
        }
        result.update(overrides)
        if "issue_set_identity" not in overrides:
            result["issue_set_identity"] = canonical_identity_streaming(
                "binary_validation_issue_set_identity",
                result["issues"],
                schema_version="1",
            )
        if "validation_run_identity" not in overrides:
            result["validation_run_identity"] = canonical_identity(
                "binary_validation_run_identity",
                {
                    "result_generation_identity": result[
                        "result_generation_identity"
                    ],
                    "active_snapshot_identities": dict(
                        manifest["active_snapshot_identities"]
                    ),
                    "oracle_support_manifest_identity": result[
                        "oracle_support_manifest_identity"
                    ],
                    "truth_set_identity": result["truth_set_identity"],
                    "issue_set_identity": result["issue_set_identity"],
                    "validation_policy_version": result[
                        "validation_policy_version"
                    ],
                    "validator_implementation_identity": result[
                        "validator_implementation_identity"
                    ],
                    "helper_identities": dict(result["helper_identities"]),
                },
                schema_version="1",
            )
        identity = result["validation_run_identity"]
        validation_dir = Path(manifest["generation_directory"]) / "validation"
        validation_dir.mkdir(exist_ok=True)
        path = validation_dir / f"{identity}.json"
        path.write_text(
            json.dumps(
                result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ) + "\n",
            encoding="utf-8",
        )
        return {**result, "validation_result_path": str(path)}

    def test_validation_identity_calculators_match_manual_contract(self):
        import binary_pipeline
        import binary_validation_oracle

        expected = self.expected_validator_implementation_identity()
        support = json.loads(
            (ROOT_DIR / "scripts" / "binary_first_support_manifest.json")
            .read_text(encoding="utf-8")
        )
        expected_support = canonical_identity(
            "oracle_support_manifest_identity",
            support["oracle_support_manifest"],
            schema_version="1",
        )

        self.assertEqual(
            tuple(validation_contract.VALIDATOR_IMPLEMENTATION_SOURCE_PATHS),
            (
                "artifact_safety.py",
                "binary_first_contract.py",
                "binary_tool_execution.py",
                "binary_validation_contract.py",
                "binary_validation_oracle.py",
                "compat.py",
                "edge_truth.py",
                "final_artifact_edge_oracle.py",
                "jdk_preflight.py",
                "javap_contract.py",
                "java/RuntimeOutcomeOracle.java",
                "path_runtime.py",
                "streaming_json.py",
            ),
        )
        self.assertEqual(
            validation_contract.validator_implementation_identity(), expected
        )
        self.assertEqual(
            binary_pipeline._current_validator_implementation_identity(),
            expected,
        )
        self.assertEqual(
            binary_validation_oracle.POLICY_VERSION,
            validation_contract.VALIDATION_POLICY_VERSION,
        )
        self.assertEqual(
            validation_contract.oracle_support_manifest_identity(),
            expected_support,
        )
        self.assertEqual(
            binary_pipeline._current_oracle_support_manifest_identity(),
            expected_support,
        )

    def test_validation_dependency_change_does_not_block_loaded_validator(self):
        original = validation_contract.validator_implementation_identity()
        changed_sources = dict(
            validation_contract._CAPTURED_VALIDATOR_SOURCE_DIGESTS
        )
        changed_sources["edge_truth.py"] = "0" * 64
        changed = (
            validation_contract._validator_implementation_identity_from_inputs(
                changed_sources,
                validation_contract._CAPTURED_PYTHON_RUNTIME_IDENTITY,
            )
        )

        self.assertNotEqual(original, changed)
        with patch.object(
            validation_contract,
            "_validator_source_digests",
            return_value=changed_sources,
        ):
            self.assertEqual(
                validation_contract.validator_implementation_identity(),
                original,
            )

    def test_oracle_support_metadata_change_does_not_block_loaded_validator(self):
        changed_support = json.loads(json.dumps(
            validation_contract._CAPTURED_ORACLE_SUPPORT_MANIFEST
        ))
        changed_support["direct_edge_oracle_policy"] = (
            "changed-after-module-load"
        )

        with patch.object(
            validation_contract,
            "_load_oracle_support_manifest",
            return_value=changed_support,
        ):
            self.assertEqual(
                validation_contract.oracle_support_manifest_identity(),
                validation_contract._CAPTURED_ORACLE_SUPPORT_MANIFEST_IDENTITY,
            )

    def test_writes_immutable_generation_with_four_bound_dimensions(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            first = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            second = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            validation = self.validation_result(first)
            activate_binary_generation(tmp, first, validation_result=validation)
            generation = Path(first["generation_directory"])
            manifest = json.loads((generation / "result_generation.json").read_text())
            active = json.loads((Path(tmp) / "active_binary_generation.json").read_text())
            validation_sha256 = hashlib.sha256(
                Path(validation["validation_result_path"]).read_bytes()
            ).hexdigest()
            formal = json.loads((generation / "binary_formal_results.json").read_text())
            obsolete_attachment_exists = (
                generation / "generation_attachments.json"
            ).exists()
            with (generation / "binary_formal_results.csv").open(newline="") as handle:
                csv_rows = list(csv.DictReader(handle))
            actual_sidecar_identities = {
                name: hashlib.sha256((generation / name).read_bytes()).hexdigest()
                for name in manifest["sidecar_content_identities"]
            }

        self.assertEqual(first["result_generation_identity"], second["result_generation_identity"])
        self.assertEqual(active["result_generation_identity"], manifest["result_generation_identity"])
        self.assertEqual(
            active["validation_result_sha256"], validation_sha256,
        )
        self.assertFalse(obsolete_attachment_exists)
        self.assertEqual(
            manifest["attachment_policy"],
            "trace-results-content-bound-in-generation-sidecars-v2",
        )
        self.assertIn("generation_attachment", manifest["policy_identities"])
        by_api = formal["by_api"][0]
        self.assertEqual(by_api["reachability_status"], "reachable")
        self.assertEqual(by_api["impact_conclusion"], "probable_impact")
        self.assertEqual(by_api["runtime_verification_status"], "required_not_executed")
        self.assertTrue(by_api["path_set_complete"])
        self.assertEqual(csv_rows[0]["reachability_status"], "reachable")
        for name, expected in manifest["sidecar_content_identities"].items():
            self.assertEqual(actual_sidecar_identities[name], expected)

    def test_generation_publish_is_root_durable_before_activation_handoff(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        events = []
        real_replace = binary_output.os.replace

        def synchronize_file(path):
            events.append(("file", Path(path)))

        def synchronize_directory(path):
            events.append(("directory", Path(path)))
            return True

        def replace_with_event(source, destination):
            source_path = Path(source)
            destination_path = Path(destination)
            if source_path.name.startswith("binary-generation-"):
                events.append(("replace", source_path, destination_path))
            return real_replace(source, destination)

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_output,
            "_fsync_regular_file",
            side_effect=synchronize_file,
        ), patch.object(
            binary_output,
            "_fsync_directory",
            side_effect=synchronize_directory,
        ), patch.object(
            binary_output.os,
            "replace",
            side_effect=replace_with_event,
        ):
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            destination = Path(manifest["generation_directory"])

        replace_index = next(
            index for index, event in enumerate(events)
            if event[0] == "replace"
        )
        temporary = events[replace_index][1]
        generations = destination.parent
        root = generations.parent
        expected_files = set(manifest["sidecar_content_identities"])
        expected_files.add("result_generation.json")
        pre_replace_files = {
            event[1].name for event in events[:replace_index]
            if event[0] == "file" and event[1].parent == temporary
        }
        self.assertEqual(pre_replace_files, expected_files)
        self.assertEqual(
            [
                event[1].name for event in events
                if event[0] == "file" and event[1].parent == temporary
            ],
            [
                *manifest["sidecar_content_identities"],
                "result_generation.json",
            ],
        )
        self.assertFalse(any(
            event[0] == "file" and event[1].parent == destination
            for event in events
        ))
        self.assertEqual(
            [event for event in events if event[0] == "directory"],
            [
                ("directory", temporary),
                ("directory", generations),
                ("directory", root),
            ],
        )
        self.assertEqual(events[replace_index - 1], ("directory", temporary))
        self.assertEqual(events[replace_index + 1], ("directory", generations))
        self.assertEqual(events[replace_index + 2], ("directory", root))
        self.assertFalse((root / "active_binary_generation.json").exists())

    def test_generation_writer_uses_one_physical_output_root_contract(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            missing_root = base / "missing" / "runtime" / "binary"
            missing_manifest = write_binary_generation(
                missing_root,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "missing-root"},
            )
            self.assertTrue(missing_root.is_dir())
            self.assertTrue(
                Path(missing_manifest["generation_directory"]).is_dir()
            )

            physical_parent = base / "physical-parent"
            physical_parent.mkdir()
            linked_parent = base / "linked-parent"
            try:
                linked_parent.symlink_to(
                    physical_parent, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")
            linked_root = linked_parent / "new" / "binary"
            linked_manifest = write_binary_generation(
                linked_root,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "linked-ancestor"},
            )
            expected_root = physical_parent / "new" / "binary"
            self.assertEqual(
                Path(linked_manifest["generation_directory"]).parent.parent,
                expected_root,
            )
            self.assertTrue(expected_root.is_dir())

            for kind in ("directory_link", "dangling_link", "file"):
                with self.subTest(kind=kind):
                    leaf = base / f"unsafe-{kind}"
                    external = base / f"external-{kind}"
                    sentinel = external / "sentinel.txt"
                    if kind == "directory_link":
                        external.mkdir()
                        sentinel.write_text("unchanged", encoding="utf-8")
                        leaf.symlink_to(external, target_is_directory=True)
                    elif kind == "dangling_link":
                        leaf.symlink_to(external, target_is_directory=True)
                    else:
                        leaf.write_bytes(b"occupied")
                    with self.assertRaises(BinaryOutputError) as caught:
                        write_binary_generation(
                            leaf,
                            decisions,
                            traces,
                            profile,
                            policy_identities={"registry": kind},
                        )
                    self.assertEqual(
                        caught.exception.reason_code,
                        "BINARY_OUTPUT_ROOT_INVALID",
                    )
                    if kind == "directory_link":
                        self.assertEqual(
                            sentinel.read_text(encoding="utf-8"), "unchanged"
                        )
                        self.assertEqual(
                            sorted(path.name for path in external.iterdir()),
                            ["sentinel.txt"],
                        )
                    elif kind == "dangling_link":
                        self.assertFalse(external.exists())
                    else:
                        self.assertEqual(leaf.read_bytes(), b"occupied")

            raced_leaf = base / "raced-leaf"
            raced_external = base / "raced-external"
            raced_external.mkdir()
            sentinel = raced_external / "sentinel.txt"
            sentinel.write_text("unchanged", encoding="utf-8")

            def install_link_before_leaf_recheck(path, _mode):
                self.assertEqual(Path(path), raced_leaf)
                raced_leaf.symlink_to(
                    raced_external, target_is_directory=True
                )
                raise FileExistsError(str(path))

            with patch.object(
                binary_output.os,
                "mkdir",
                side_effect=install_link_before_leaf_recheck,
            ), patch.object(binary_output, "build_output_payloads") as build:
                with self.assertRaises(BinaryOutputError) as caught:
                    write_binary_generation(
                        raced_leaf,
                        decisions,
                        traces,
                        profile,
                        policy_identities={"registry": "raced"},
                    )
            self.assertEqual(
                caught.exception.reason_code, "BINARY_OUTPUT_ROOT_INVALID"
            )
            build.assert_not_called()
            self.assertEqual(
                sentinel.read_text(encoding="utf-8"), "unchanged"
            )

    def test_generation_writer_rejects_symlinked_generation_namespace_without_escape(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            root = base / "output"
            outside = base / "outside-generations"
            root.mkdir()
            outside.mkdir()
            sentinel = outside / "sentinel.txt"
            sentinel.write_bytes(b"unchanged")
            try:
                (root / "binary_generations").symlink_to(
                    outside, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            with patch.object(
                binary_output, "build_output_payloads"
            ) as build_payloads:
                with self.assertRaises(BinaryOutputError) as caught:
                    write_binary_generation(
                        root,
                        decisions,
                        traces,
                        profile,
                        policy_identities={"registry": "namespace-link"},
                    )

            self.assertEqual(
                caught.exception.reason_code, "BINARY_OUTPUT_ROOT_INVALID"
            )
            build_payloads.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"unchanged")
            self.assertEqual(
                sorted(path.name for path in outside.iterdir()),
                ["sentinel.txt"],
            )

    def test_generation_writer_rejects_symlinked_content_addressed_leaf_without_escape(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        policy = {"registry": "generation-link"}
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            seed = write_binary_generation(
                base / "seed",
                decisions,
                traces,
                profile,
                policy_identities=policy,
            )
            external_generation = Path(seed["generation_directory"])
            sentinel = external_generation / "sentinel.txt"
            sentinel.write_bytes(b"unchanged")
            before = {
                str(path.relative_to(external_generation)): path.read_bytes()
                for path in external_generation.rglob("*")
                if path.is_file()
            }
            root = base / "output"
            generations = root / "binary_generations"
            generations.mkdir(parents=True)
            linked_generation = generations / seed[
                "result_generation_identity"
            ]
            try:
                linked_generation.symlink_to(
                    external_generation, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            with self.assertRaises(BinaryOutputError) as caught:
                write_binary_generation(
                    root,
                    decisions,
                    traces,
                    profile,
                    policy_identities=policy,
                )

            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_GENERATION_IDENTITY_COLLISION",
            )
            after = {
                str(path.relative_to(external_generation)): path.read_bytes()
                for path in external_generation.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)
            self.assertEqual(sentinel.read_bytes(), b"unchanged")
            self.assertTrue(linked_generation.is_symlink())

    def test_public_generation_reads_reject_nested_links_without_external_mutation(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            seed_root = base / "seed"
            manifest = write_binary_generation(
                seed_root,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "nested-read"},
            )
            validation = self.validation_result(manifest)
            self._activate_sealed(seed_root, manifest, validation)
            seed_generations = seed_root / "binary_generations"
            seed_generation = Path(manifest["generation_directory"])
            sentinel = seed_generation / "sentinel.txt"
            sentinel.write_bytes(b"unchanged")
            active_bytes = (
                seed_root / "active_binary_generation.json"
            ).read_bytes()
            before = {
                str(path.relative_to(seed_generations)): path.read_bytes()
                for path in seed_generations.rglob("*")
                if path.is_file()
            }

            for link_level in ("namespace", "generation"):
                with self.subTest(link_level=link_level):
                    root = base / f"victim-{link_level}"
                    root.mkdir()
                    (root / "active_binary_generation.json").write_bytes(
                        active_bytes
                    )
                    try:
                        if link_level == "namespace":
                            (root / "binary_generations").symlink_to(
                                seed_generations, target_is_directory=True
                            )
                        else:
                            generations = root / "binary_generations"
                            generations.mkdir()
                            (generations / manifest[
                                "result_generation_identity"
                            ]).symlink_to(
                                seed_generation, target_is_directory=True
                            )
                    except OSError as error:
                        self.skipTest(
                            f"directory symlinks unavailable: {error}"
                        )

                    with self.assertRaises(BinaryOutputError) as read_error:
                        binary_output.read_active_binary_generation(root)
                    self.assertEqual(
                        read_error.exception.reason_code,
                        "BINARY_GENERATION_MANIFEST_INVALID",
                    )

                    with self.assertRaises(BinaryOutputError) as commit_error:
                        binary_output.commit_pending_binary_generation(
                            root,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity="a" * 64,
                        )
                    self.assertEqual(
                        commit_error.exception.reason_code,
                        "BINARY_GENERATION_MANIFEST_INVALID",
                    )
                    self.assertEqual(
                        (root / "active_binary_generation.json").read_bytes(),
                        active_bytes,
                    )
                    after = {
                        str(path.relative_to(seed_generations)): path.read_bytes()
                        for path in seed_generations.rglob("*")
                        if path.is_file()
                    }
                    self.assertEqual(after, before)
                    self.assertEqual(sentinel.read_bytes(), b"unchanged")

    def test_public_output_apis_reject_root_leaf_symlink_without_mutation(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        operations = ("write", "activate", "publish", "seal", "rollback", "commit")
        for operation in operations:
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                physical = base / "physical-output"
                manifest = write_binary_generation(
                    physical,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": operation},
                )
                validation = self.validation_result(manifest)
                activation = hashlib.sha256(
                    operation.encode("utf-8")
                ).hexdigest()
                if operation in {"publish", "commit"}:
                    activate_binary_generation(
                        physical,
                        manifest,
                        validation_result=validation,
                        activation_identity=activation,
                        defer_publication=True,
                    )
                    if operation == "commit":
                        self.assertTrue(
                            binary_output.publish_pending_binary_generation(
                                physical,
                                expected_current_identity=manifest[
                                    "result_generation_identity"
                                ],
                                expected_activation_identity=activation,
                            )
                        )
                elif operation in {"seal", "rollback"}:
                    activate_binary_generation(
                        physical,
                        manifest,
                        validation_result=validation,
                        activation_identity=activation,
                    )
                sentinel = physical / "sentinel.txt"
                sentinel.write_text("unchanged", encoding="utf-8")
                alias = base / "output-alias"
                try:
                    alias.symlink_to(physical, target_is_directory=True)
                except OSError as error:
                    self.skipTest(f"directory symlinks unavailable: {error}")
                descriptor_paths = (
                    physical / "active_binary_generation.json",
                    physical
                    / "binary_observability"
                    / "pending_active_binary_generation.json",
                )
                descriptor_bytes = {
                    path: path.read_bytes() if path.exists() else None
                    for path in descriptor_paths
                }

                with self.assertRaises(BinaryOutputError):
                    if operation == "write":
                        write_binary_generation(
                            alias,
                            decisions,
                            traces,
                            profile,
                            policy_identities={"registry": "alias"},
                        )
                    elif operation == "activate":
                        activate_binary_generation(
                            alias,
                            manifest,
                            validation_result=validation,
                            activation_identity=activation,
                        )
                    elif operation == "publish":
                        binary_output.publish_pending_binary_generation(
                            alias,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity=activation,
                        )
                    elif operation == "seal":
                        seal_active_binary_generation(
                            alias,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity=activation,
                        )
                    elif operation == "rollback":
                        compare_and_restore_active_binary_generation(
                            alias,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity=activation,
                        )
                    else:
                        binary_output.commit_pending_binary_generation(
                            alias,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity=activation,
                        )

                self.assertEqual(
                    sentinel.read_text(encoding="utf-8"), "unchanged"
                )
                self.assertEqual(
                    {
                        path: path.read_bytes() if path.exists() else None
                        for path in descriptor_paths
                    },
                    descriptor_bytes,
                )

    def test_existing_generation_reestablishes_durability_once(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            first = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            events = []

            def prove_generation(*_args, **_kwargs):
                events.append("generation")

            def synchronize_root(path):
                events.append(("root", Path(path)))
                return True

            with patch.object(
                binary_output,
                "_make_generation_durable",
                side_effect=prove_generation,
            ) as durability_barrier, patch.object(
                binary_output,
                "_fsync_directory",
                side_effect=synchronize_root,
            ) as root_sync:
                second = write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"projection_registry": "registry-1"},
                )

        self.assertEqual(
            second["result_generation_identity"],
            first["result_generation_identity"],
        )
        durability_barrier.assert_called_once()
        barrier_generation, barrier_files = durability_barrier.call_args.args
        self.assertEqual(Path(barrier_generation), Path(first["generation_directory"]))
        self.assertEqual(
            set(barrier_files),
            {*first["sidecar_content_identities"], "result_generation.json"},
        )
        root_sync.assert_called_once_with(Path(tmp).resolve())
        self.assertEqual(
            events, ["generation", ("root", Path(tmp).resolve())]
        )

    def test_lost_generation_publication_race_reestablishes_durability_once(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        real_replace = binary_output.os.replace

        def publish_then_report_race(source, destination):
            source_path = Path(source)
            if source_path.name.startswith("binary-generation-"):
                # Model an equivalent concurrent publisher winning between the
                # existence check and our rename.  Moving these already-built
                # bytes creates the exact valid destination that the loser
                # must independently synchronize.
                real_replace(source, destination)
                raise OSError(errno.EEXIST, "generation already published")
            return real_replace(source, destination)

        directory_sync = Mock(return_value=True)
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_output.os,
            "replace",
            side_effect=publish_then_report_race,
        ), patch.object(
            binary_output, "_make_generation_durable"
        ) as durability_barrier, patch.object(
            binary_output, "_fsync_directory", directory_sync
        ):
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )

        durability_barrier.assert_called_once()
        barrier_generation, barrier_files = durability_barrier.call_args.args
        self.assertEqual(
            Path(barrier_generation), Path(manifest["generation_directory"])
        )
        self.assertEqual(
            set(barrier_files),
            {*manifest["sidecar_content_identities"], "result_generation.json"},
        )
        self.assertEqual(
            Path(directory_sync.call_args_list[-1].args[0]),
            Path(tmp).resolve(),
        )

    def test_generation_root_durability_failure_prevents_validation_handoff(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()

            def synchronize(path):
                if Path(path) == root:
                    raise OSError("output root durability failure")
                return True

            with patch.object(
                binary_output,
                "_fsync_directory",
                side_effect=synchronize,
            ), self.assertRaisesRegex(
                OSError, "output root durability failure"
            ):
                write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"projection_registry": "registry-1"},
                )

            self.assertFalse(
                (root / "active_binary_generation.json").exists()
            )

    def test_generation_cleanup_preserves_primary_and_attempts_both_trees(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        primary = RuntimeError("generation copy primary")
        cleanup = Mock(side_effect=(
            OSError("generation cleanup"),
            OSError("staging cleanup"),
        ))
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_output.shutil,
            "copyfile",
            side_effect=primary,
        ), patch.object(
            binary_output,
            "_rmtree_missing_ok",
            cleanup,
        ):
            with self.assertRaises(RuntimeError) as caught:
                write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"projection_registry": "registry-1"},
                )

        self.assertIs(caught.exception, primary)
        self.assertEqual(cleanup.call_count, 2)
        notes = list(getattr(primary, "__notes__", ()))
        self.assertTrue(any("generation cleanup" in note for note in notes))
        self.assertTrue(any("staging cleanup" in note for note in notes))

    def test_generation_cleanup_failure_is_fatal_without_primary(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_output,
            "_rmtree_missing_ok",
            side_effect=OSError("staging cleanup only"),
        ):
            with self.assertRaisesRegex(OSError, "staging cleanup only"):
                write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"projection_registry": "registry-1"},
                )

    def test_activation_durability_barrier_precedes_active_descriptor(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            validation = self.validation_result(manifest)
            validation_path = Path(validation["validation_result_path"]).resolve()
            events = []

            def synchronize_file(path):
                events.append(("file", Path(path)))

            def synchronize_directory(path):
                events.append(("directory", Path(path)))
                return True

            def write_active(root, active, **_kwargs):
                events.append(("active", Path(root)))
                return Path(root) / "active_binary_generation.json"

            with patch.object(
                binary_output,
                "_fsync_regular_file",
                side_effect=synchronize_file,
            ), patch.object(
                binary_output,
                "_fsync_directory",
                side_effect=synchronize_directory,
            ), patch.object(
                binary_output, "_write_active_descriptor", side_effect=write_active
            ):
                activate_binary_generation(
                    tmp, manifest, validation_result=validation
                )

        generation = Path(manifest["generation_directory"]).resolve()
        expected_files = {
            *(generation / name for name in manifest["sidecar_content_identities"]),
            generation / "result_generation.json",
            validation_path,
        }
        self.assertEqual(
            {event[1] for event in events if event[0] == "file"},
            expected_files,
        )
        self.assertEqual(
            [event[1] for event in events if event[0] == "directory"],
            [
                validation_path.parent,
                generation,
                generation.parent,
                Path(tmp).resolve(),
            ],
        )
        self.assertEqual(events[-1], ("active", Path(tmp).resolve()))

    def test_activation_does_not_publish_when_root_durability_fails(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            validation = self.validation_result(manifest)
            write_active = Mock()
            with patch.object(
                binary_output, "_make_generation_durable"
            ), patch.object(
                binary_output,
                "_fsync_directory",
                side_effect=OSError("output root durability failure"),
            ), patch.object(
                binary_output,
                "_write_active_descriptor",
                write_active,
            ):
                with self.assertRaisesRegex(
                    OSError, "output root durability failure"
                ):
                    activate_binary_generation(
                        tmp, manifest, validation_result=validation
                    )

            self.assertFalse(
                (Path(tmp) / "active_binary_generation.json").exists()
            )
        write_active.assert_not_called()

    def test_activation_does_not_publish_after_durability_io_failure(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            validation = self.validation_result(manifest)
            write_active = Mock()
            with patch.object(
                binary_output,
                "_fsync_regular_file",
                side_effect=OSError("durability media failure"),
            ), patch.object(
                binary_output,
                "_write_active_descriptor",
                write_active,
            ):
                with self.assertRaisesRegex(OSError, "durability media failure"):
                    activate_binary_generation(
                        tmp, manifest, validation_result=validation
                    )

            self.assertFalse(
                (Path(tmp) / "active_binary_generation.json").exists()
            )
        write_active.assert_not_called()

    def test_entrypoint_sidecar_persists_discovery_coverage_evidence(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        traces = replace(
            traces,
            entrypoint_coverage_status="partial",
            entrypoint_coverage_gaps=(
                "packaged_main_class_manifest_missing",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            entrypoints = json.loads(
                (
                    Path(manifest["generation_directory"])
                    / "binary_entrypoints.json"
                ).read_text(encoding="utf-8")
            )

        self.assertEqual(entrypoints["coverage_status"], "partial")
        self.assertEqual(
            entrypoints["coverage_gaps"],
            ["packaged_main_class_manifest_missing"],
        )

    def test_activation_and_reuse_reject_transient_sqlite_sidecars(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        for transient_name in (
            "base_binary_facts.sqlite-wal",
            "base_binary_facts.sqlite-shm",
            "base_binary_facts.sqlite-journal",
            "current_binary_facts.sqlite-wal",
            "current_binary_facts.sqlite-shm",
            "current_binary_facts.sqlite-journal",
        ):
            with self.subTest(transient_name=transient_name), tempfile.TemporaryDirectory() as tmp:
                manifest = write_binary_generation(
                    tmp, decisions, traces, profile,
                    policy_identities={"registry": "v1"},
                )
                generation = Path(manifest["generation_directory"])
                (generation / transient_name).write_bytes(b"transient")
                validation = self.validation_result(manifest)

                with self.assertRaises(BinaryOutputError) as activation_error:
                    activate_binary_generation(
                        tmp, manifest, validation_result=validation
                    )
                with self.assertRaises(BinaryOutputError) as reuse_error:
                    write_binary_generation(
                        tmp, decisions, traces, profile,
                        policy_identities={"registry": "v1"},
                    )

                self.assertEqual(
                    activation_error.exception.reason_code,
                    "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED",
                )
                self.assertEqual(
                    reuse_error.exception.reason_code,
                    "BINARY_GENERATION_IDENTITY_COLLISION",
                )

    def test_obsolete_unbound_generation_attachment_is_rejected(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            generation = Path(manifest["generation_directory"])
            (generation / "generation_attachments.json").write_text(
                '{"tampered":true}\n', encoding="utf-8"
            )
            validation = self.validation_result(manifest)

            with self.assertRaises(BinaryOutputError) as activation_error:
                activate_binary_generation(
                    tmp, manifest, validation_result=validation
                )
            with self.assertRaises(BinaryOutputError) as reuse_error:
                write_binary_generation(
                    tmp, decisions, traces, profile,
                    policy_identities={"registry": "v1"},
                )

        self.assertEqual(
            activation_error.exception.reason_code,
            "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED",
        )
        self.assertEqual(
            reuse_error.exception.reason_code,
            "BINARY_GENERATION_IDENTITY_COLLISION",
        )

    def test_concurrent_identical_generation_publication_is_idempotent(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            def publish():
                return write_binary_generation(
                    tmp, decisions, traces, profile,
                    policy_identities={"projection_registry": "registry-1"},
                )

            with ThreadPoolExecutor(max_workers=4) as executor:
                manifests = list(executor.map(lambda _index: publish(), range(8)))
            identities = {
                item["result_generation_identity"] for item in manifests
            }
            generation_dirs = list((Path(tmp) / "binary_generations").iterdir())
            manifest = json.loads((
                generation_dirs[0] / "result_generation.json"
            ).read_text(encoding="utf-8"))

        self.assertEqual(len(identities), 1)
        self.assertEqual(len(generation_dirs), 1)
        self.assertEqual(manifest["result_generation_identity"], next(iter(identities)))

    def test_existing_generation_manifest_payload_identity_tampering_collides(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            manifest_path = Path(manifest["generation_directory"]) / "result_generation.json"
            persisted = json.loads(manifest_path.read_text(encoding="utf-8"))
            persisted["policy_identities"] = {"registry": "v2"}
            manifest_path.write_text(json.dumps(persisted), encoding="utf-8")

            with self.assertRaises(BinaryOutputError) as error:
                write_binary_generation(
                    tmp, decisions, traces, profile,
                    policy_identities={"registry": "v1"},
                )

            self.assertEqual(
                error.exception.reason_code, "BINARY_GENERATION_IDENTITY_COLLISION"
            )

    def test_unreachable_api_keeps_runtime_verification_undetermined(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        formal = dict(traces.formal_results[0])
        formal.update({
            "reachability_status": "not_found_in_static_analysis",
            "analysis_status": "not_found_in_static_analysis",
            "is_reachable": False,
            "impact_conclusion": "inconclusive",
            "runtime_verification_status": "undetermined",
            "exact_path_exists": False,
        })
        unreachable_traces = replace(traces, formal_results=(formal,))

        by_api = _aggregate_by_api(decisions, unreachable_traces, profile)[0]

        self.assertEqual(
            by_api["runtime_verification_status"], "undetermined"
        )

    def test_api_runtime_verification_is_derived_from_reachability(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        inconsistent_formal = dict(traces.formal_results[0])
        inconsistent_formal["runtime_verification_status"] = "undetermined"

        by_api = _aggregate_by_api(
            decisions,
            replace(traces, formal_results=(inconsistent_formal,)),
            profile,
        )[0]

        self.assertEqual(
            by_api["runtime_verification_status"], "required_not_executed"
        )

    def test_large_path_sidecar_is_streamed_and_content_bound(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "facts.sqlite"
            source.write_bytes((b"binary-fact-block" * 65536) + b"tail")
            manifest = write_binary_generation(
                Path(tmp) / "output", decisions, traces, profile,
                policy_identities={"registry": "v1"},
                additional_sidecars={"facts.sqlite": source},
            )
            copied = Path(manifest["generation_directory"]) / "facts.sqlite"
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            copied_digest = hashlib.sha256(copied.read_bytes()).hexdigest()

        self.assertEqual(manifest["sidecar_content_identities"]["facts.sqlite"], expected)
        self.assertEqual(copied_digest, expected)

    def test_existing_generation_tampering_fails_without_moving_active_pointer(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            first = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            activate_binary_generation(
                tmp, first, validation_result=self.validation_result(first)
            )
            active_before = (Path(tmp) / "active_binary_generation.json").read_bytes()
            generation = Path(first["generation_directory"])
            (generation / "binary_summary.json").write_text("tampered", encoding="utf-8")

            with self.assertRaises(BinaryOutputError) as error:
                write_binary_generation(
                    tmp, decisions, traces, profile,
                    policy_identities={"registry": "v1"},
                )

            active_after = (Path(tmp) / "active_binary_generation.json").read_bytes()
        self.assertEqual(error.exception.reason_code, "BINARY_GENERATION_IDENTITY_COLLISION")
        self.assertEqual(active_before, active_after)

    def test_active_generation_compare_and_restore_never_clobbers_newer_writer(self):
        old_identity = "0" * 64
        attempted_identity = "a" * 64
        newer_identity = "b" * 64
        previous = {
            "schema": "java-upgrade-analyzer.active-binary-generation.v1",
            "result_generation_identity": old_identity,
            "generation_directory": f"binary_generations/{old_identity}",
            "validation_run_identity": "1" * 64,
            "validation_result_sha256": "2" * 64,
        }
        activation_identity = "c" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            active_path = root / "active_binary_generation.json"
            active_path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": attempted_identity,
                "generation_directory": f"binary_generations/{attempted_identity}",
                "validation_run_identity": "3" * 64,
                "validation_result_sha256": "4" * 64,
                "activation_identity": activation_identity,
                "activation_predecessor": previous,
            }), encoding="utf-8")
            self.assertTrue(compare_and_restore_active_binary_generation(
                root,
                expected_current_identity=attempted_identity,
                expected_activation_identity=activation_identity,
                previous_active=previous,
            ))
            restored = json.loads(active_path.read_text(encoding="utf-8"))

            active_path.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": newer_identity,
                "generation_directory": f"binary_generations/{newer_identity}",
                "validation_run_identity": "5" * 64,
                "validation_result_sha256": "6" * 64,
                "activation_identity": "d" * 64,
                "activation_predecessor": previous,
            }), encoding="utf-8")
            self.assertFalse(compare_and_restore_active_binary_generation(
                root,
                expected_current_identity=attempted_identity,
                expected_activation_identity=activation_identity,
                previous_active=previous,
            ))
            preserved = json.loads(active_path.read_text(encoding="utf-8"))

        self.assertEqual(restored["result_generation_identity"], old_identity)
        self.assertEqual(preserved["result_generation_identity"], newer_identity)

    def test_active_descriptor_operations_reject_links_and_fifo(self):
        generation = "a" * 64
        activation = "b" * 64
        descriptor = {
            "schema": "java-upgrade-analyzer.active-binary-generation.v1",
            "result_generation_identity": generation,
            "generation_directory": f"binary_generations/{generation}",
            "validation_run_identity": "c" * 64,
            "validation_result_sha256": "d" * 64,
            "activation_identity": activation,
            "activation_predecessor": None,
        }
        operations = (
            lambda root: compare_and_restore_active_binary_generation(
                root,
                expected_current_identity=generation,
                expected_activation_identity=activation,
            ),
            lambda root: seal_active_binary_generation(
                root,
                expected_current_identity=generation,
                expected_activation_identity=activation,
            ),
        )
        for operation_index, operation in enumerate(operations):
            for kind in ("symlink", "hardlink", "fifo"):
                with self.subTest(operation=operation_index, kind=kind):
                    with tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp).resolve()
                        active = root / "active_binary_generation.json"
                        target = root / "external.json"
                        original = json.dumps(descriptor).encode("utf-8")
                        if kind == "fifo":
                            if not hasattr(os, "mkfifo"):
                                self.skipTest("FIFO is unavailable")
                            try:
                                os.mkfifo(active)
                            except OSError as error:
                                self.skipTest(f"FIFO is unavailable: {error}")
                        else:
                            target.write_bytes(original)
                            try:
                                if kind == "symlink":
                                    active.symlink_to(target)
                                else:
                                    os.link(target, active)
                            except OSError as error:
                                self.skipTest(f"{kind} is unavailable: {error}")

                        with self.assertRaises(BinaryOutputError) as caught:
                            operation(root)

                        self.assertEqual(
                            caught.exception.reason_code,
                            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
                        )
                        if kind != "fifo":
                            self.assertEqual(target.read_bytes(), original)

    def test_active_descriptor_read_detects_replacement_during_open(self):
        generation = "a" * 64
        activation = "b" * 64

        def descriptor(identity, token):
            return {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": identity,
                "generation_directory": f"binary_generations/{identity}",
                "validation_run_identity": "c" * 64,
                "validation_result_sha256": "d" * 64,
                "activation_identity": token,
                "activation_predecessor": None,
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            active = root / "active_binary_generation.json"
            replacement = root / "replacement.json"
            active.write_text(
                json.dumps(descriptor(generation, activation)), encoding="utf-8"
            )
            replacement_generation = "e" * 64
            replacement.write_text(json.dumps(descriptor(
                replacement_generation, "f" * 64
            )), encoding="utf-8")
            real_open = os.open
            replaced = False

            def replace_before_open(path, flags, *args, **kwargs):
                nonlocal replaced
                if Path(path) == active and not replaced:
                    replaced = True
                    os.replace(replacement, active)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(binary_output.os, "open", replace_before_open):
                with self.assertRaises(BinaryOutputError) as caught:
                    seal_active_binary_generation(
                        root,
                        expected_current_identity=generation,
                        expected_activation_identity=activation,
                    )
            preserved = json.loads(active.read_text(encoding="utf-8"))

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
        )
        self.assertEqual(
            preserved["result_generation_identity"], replacement_generation
        )

    def test_activation_rollback_uses_lock_observed_predecessor_not_stale_snapshot(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifests = [
                write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": label},
                )
                for label in ("A", "B", "C")
            ]
            tokens = ("a" * 64, "b" * 64, "c" * 64)
            for manifest, token in zip(manifests[:2], tokens[:2]):
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=self.validation_result(manifest),
                    activation_identity=token,
                )
            stale_step4_snapshot = manifests[0]["result_generation_identity"]
            activation_record = {}
            activate_binary_generation(
                tmp,
                manifests[2],
                validation_result=self.validation_result(manifests[2]),
                activation_identity=tokens[2],
                activation_record=activation_record,
            )
            self.assertEqual(
                activation_record["activation_predecessor"][
                    "result_generation_identity"
                ],
                manifests[1]["result_generation_identity"],
            )

            restored = compare_and_restore_active_binary_generation(
                tmp,
                expected_current_identity=manifests[2][
                    "result_generation_identity"
                ],
                expected_activation_identity=tokens[2],
                previous_active=activation_record["activation_predecessor"],
            )
            active = json.loads(
                (Path(tmp) / "active_binary_generation.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertTrue(restored)
        self.assertNotEqual(
            active["result_generation_identity"], stale_step4_snapshot
        )
        self.assertEqual(
            active["result_generation_identity"],
            manifests[1]["result_generation_identity"],
        )

    def test_private_activation_candidate_never_changes_public_before_commit(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            old_manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "old"},
            )
            self._activate_sealed(
                tmp, old_manifest, self.validation_result(old_manifest)
            )
            public_path = Path(tmp) / "active_binary_generation.json"
            old_public_bytes = public_path.read_bytes()
            new_manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "new"},
            )
            activation = "e" * 64
            candidate_path = Path(activate_binary_generation(
                tmp,
                new_manifest,
                validation_result=self.validation_result(new_manifest),
                activation_identity=activation,
                defer_publication=True,
            ))

            self.assertEqual(public_path.read_bytes(), old_public_bytes)
            self.assertEqual(
                binary_output.read_active_binary_generation(tmp)[
                    "result_generation_identity"
                ],
                old_manifest["result_generation_identity"],
            )
            self.assertEqual(
                binary_output.read_pending_binary_generation(tmp)[
                    "result_generation_identity"
                ],
                new_manifest["result_generation_identity"],
            )
            self.assertTrue(candidate_path.is_file())

            self.assertTrue(binary_output.publish_pending_binary_generation(
                tmp,
                expected_current_identity=new_manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            ))
            self.assertEqual(
                binary_output.read_active_binary_generation(tmp)[
                    "result_generation_identity"
                ],
                new_manifest["result_generation_identity"],
            )
            self.assertTrue(compare_and_restore_active_binary_generation(
                tmp,
                expected_current_identity=new_manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            ))
            self.assertEqual(public_path.read_bytes(), old_public_bytes)
            self.assertIsNone(binary_output.read_pending_binary_generation(
                tmp, missing_ok=True
            ))

            activate_binary_generation(
                tmp,
                new_manifest,
                validation_result=self.validation_result(new_manifest),
                activation_identity=activation,
                defer_publication=True,
            )
            self.assertTrue(binary_output.publish_pending_binary_generation(
                tmp,
                expected_current_identity=new_manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            ))
            self.assertTrue(binary_output.commit_pending_binary_generation(
                tmp,
                expected_current_identity=new_manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            ))
            committed_public_bytes = public_path.read_bytes()
            stale_rollback = compare_and_restore_active_binary_generation(
                tmp,
                expected_current_identity=new_manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            )
            self.assertFalse(stale_rollback)
            self.assertEqual(public_path.read_bytes(), committed_public_bytes)

    def test_direct_activation_cannot_take_over_deferred_receipt(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "e" * 64
        with tempfile.TemporaryDirectory() as tmp:
            old_manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "direct-takeover-old"},
            )
            self._activate_sealed(
                tmp, old_manifest, self.validation_result(old_manifest)
            )
            new_manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "direct-takeover-new"},
            )
            validation = self.validation_result(new_manifest)
            activate_binary_generation(
                tmp,
                new_manifest,
                validation_result=validation,
                activation_identity=activation,
                defer_publication=True,
            )

            with self.assertRaises(BinaryOutputError) as takeover:
                activate_binary_generation(
                    tmp,
                    new_manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )

            self.assertEqual(
                takeover.exception.reason_code,
                "BINARY_ACTIVE_GENERATION_ACTIVATION_IN_PROGRESS",
            )
            self.assertEqual(
                binary_output.read_active_binary_generation(tmp)[
                    "result_generation_identity"
                ],
                old_manifest["result_generation_identity"],
            )
            self.assertEqual(
                binary_output.read_pending_binary_generation(tmp)[
                    "activation_identity"
                ],
                activation,
            )

            # Only the deferred publication protocol may consume the receipt.
            self.assertTrue(binary_output.publish_pending_binary_generation(
                tmp,
                expected_current_identity=new_manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            ))
            self.assertTrue(binary_output.commit_pending_binary_generation(
                tmp,
                expected_current_identity=new_manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            ))
            self.assertFalse(compare_and_restore_active_binary_generation(
                tmp,
                expected_current_identity=new_manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            ))
            self.assertEqual(
                binary_output.read_active_binary_generation(tmp)[
                    "result_generation_identity"
                ],
                new_manifest["result_generation_identity"],
            )

    def test_private_candidate_tampering_fails_closed_at_publication(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        for tamper_kind in ("sidecar", "validation", "sidecar_symlink"):
            with self.subTest(tamper_kind=tamper_kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                old_manifest = write_binary_generation(
                    root,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": f"old-{tamper_kind}"},
                )
                self._activate_sealed(
                    root, old_manifest, self.validation_result(old_manifest)
                )
                active_path = root / "active_binary_generation.json"
                active_before = active_path.read_bytes()
                new_manifest = write_binary_generation(
                    root,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": f"new-{tamper_kind}"},
                )
                validation = self.validation_result(new_manifest)
                activation = hashlib.sha256(tamper_kind.encode("utf-8")).hexdigest()
                activate_binary_generation(
                    root,
                    new_manifest,
                    validation_result=validation,
                    activation_identity=activation,
                    defer_publication=True,
                )
                generation = Path(new_manifest["generation_directory"])
                if tamper_kind == "validation":
                    Path(validation["validation_result_path"]).write_text(
                        "{}\n", encoding="utf-8"
                    )
                else:
                    sidecar = generation / "binary_summary.json"
                    if tamper_kind == "sidecar":
                        sidecar.write_text("tampered\n", encoding="utf-8")
                    else:
                        external = root / "external-summary.json"
                        os.replace(sidecar, external)
                        try:
                            sidecar.symlink_to(external)
                        except OSError as error:
                            self.skipTest(f"symlinks unavailable: {error}")

                with self.assertRaises(BinaryOutputError) as caught:
                    binary_output.publish_pending_binary_generation(
                        root,
                        expected_current_identity=new_manifest[
                            "result_generation_identity"
                        ],
                        expected_activation_identity=activation,
                    )

                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                )
                self.assertEqual(active_path.read_bytes(), active_before)
                self.assertEqual(
                    binary_output.read_active_binary_generation(root)[
                        "result_generation_identity"
                    ],
                    old_manifest["result_generation_identity"],
                )
                self.assertEqual(
                    binary_output.read_pending_binary_generation(root)[
                        "activation_identity"
                    ],
                    activation,
                )

    def test_publication_guards_run_under_lock_after_integrity_revalidation(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        for mode in ("deferred", "direct"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                old_manifest = write_binary_generation(
                    root,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": f"old-{mode}"},
                )
                self._activate_sealed(
                    root, old_manifest, self.validation_result(old_manifest)
                )
                public_path = root / "active_binary_generation.json"
                public_before = public_path.read_bytes()
                new_manifest = write_binary_generation(
                    root,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": f"new-{mode}"},
                )
                validation = self.validation_result(new_manifest)
                activation = hashlib.sha256(mode.encode("utf-8")).hexdigest()
                if mode == "deferred":
                    activate_binary_generation(
                        root,
                        new_manifest,
                        validation_result=validation,
                        activation_identity=activation,
                        defer_publication=True,
                    )

                events = []
                lock_held = {"value": False}
                real_lock = binary_output.exclusive_file_lock
                real_integrity_check = (
                    binary_output._verify_pending_generation_integrity
                )

                @contextmanager
                def observed_lock(*args, **kwargs):
                    with real_lock(*args, **kwargs):
                        lock_held["value"] = True
                        try:
                            yield
                        finally:
                            lock_held["value"] = False

                def observed_integrity_check(*args, **kwargs):
                    self.assertTrue(lock_held["value"])
                    events.append("integrity")
                    return real_integrity_check(*args, **kwargs)

                def rejecting_guard():
                    self.assertTrue(lock_held["value"])
                    events.append("guard")
                    raise RuntimeError("injected publication guard failure")

                with patch.object(
                    binary_output,
                    "exclusive_file_lock",
                    side_effect=observed_lock,
                ), patch.object(
                    binary_output,
                    "_verify_pending_generation_integrity",
                    side_effect=observed_integrity_check,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "publication guard failure"
                    ):
                        if mode == "deferred":
                            binary_output.publish_pending_binary_generation(
                                root,
                                expected_current_identity=new_manifest[
                                    "result_generation_identity"
                                ],
                                expected_activation_identity=activation,
                                publication_guard=rejecting_guard,
                            )
                        else:
                            activate_binary_generation(
                                root,
                                new_manifest,
                                validation_result=validation,
                                activation_identity=activation,
                                publication_guard=rejecting_guard,
                            )

                self.assertEqual(events, ["integrity", "guard"])
                self.assertEqual(public_path.read_bytes(), public_before)
                self.assertEqual(
                    binary_output.read_active_binary_generation(root)[
                        "result_generation_identity"
                    ],
                    old_manifest["result_generation_identity"],
                )
                if mode == "deferred":
                    self.assertEqual(
                        binary_output.read_pending_binary_generation(root)[
                            "activation_identity"
                        ],
                        activation,
                    )

    def test_activation_guard_cannot_overwrite_same_inode_predecessor_change(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        for mode in ("direct", "deferred"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                old_manifest = write_binary_generation(
                    root,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": f"old-{mode}"},
                )
                self._activate_sealed(
                    root,
                    old_manifest,
                    self.validation_result(old_manifest),
                )
                active_path = root / "active_binary_generation.json"
                predecessor = json.loads(
                    active_path.read_text(encoding="utf-8")
                )
                changed_predecessor = {
                    **predecessor,
                    "validation_result_sha256": "9" * 64,
                }
                changed_bytes = binary_output._json_bytes(
                    changed_predecessor
                )
                predecessor_inode = os.lstat(active_path).st_ino
                new_manifest = write_binary_generation(
                    root,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": f"new-{mode}"},
                )
                validation = self.validation_result(new_manifest)

                def mutating_guard():
                    active_path.write_bytes(changed_bytes)
                    self.assertEqual(
                        os.lstat(active_path).st_ino, predecessor_inode
                    )

                with self.assertRaises(BinaryOutputError) as caught:
                    activate_binary_generation(
                        root,
                        new_manifest,
                        validation_result=validation,
                        activation_identity=hashlib.sha256(
                            mode.encode("utf-8")
                        ).hexdigest(),
                        defer_publication=(mode == "deferred"),
                        publication_guard=mutating_guard,
                    )

                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
                )
                self.assertEqual(active_path.read_bytes(), changed_bytes)
                self.assertIsNone(
                    binary_output.read_pending_binary_generation(
                        root, missing_ok=True
                    )
                )

    def test_deferred_activation_guard_cannot_accept_changed_existing_pending(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "8" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            manifest = write_binary_generation(
                root,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "existing-pending"},
            )
            validation = self.validation_result(manifest)
            activate_binary_generation(
                root,
                manifest,
                validation_result=validation,
                activation_identity=activation,
                defer_publication=True,
            )
            pending_path = (
                root / binary_output._PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
            )
            pending = json.loads(pending_path.read_text(encoding="utf-8"))
            changed_pending = {
                **pending,
                "validation_result_sha256": "9" * 64,
            }
            changed_bytes = binary_output._json_bytes(changed_pending)
            pending_inode = os.lstat(pending_path).st_ino

            def mutating_guard():
                pending_path.write_bytes(changed_bytes)
                self.assertEqual(os.lstat(pending_path).st_ino, pending_inode)

            with self.assertRaises(BinaryOutputError) as caught:
                activate_binary_generation(
                    root,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                    defer_publication=True,
                    publication_guard=mutating_guard,
                )

            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
            )
            self.assertEqual(pending_path.read_bytes(), changed_bytes)
            self.assertFalse(
                (root / "active_binary_generation.json").exists()
            )

    def test_direct_activation_guard_cannot_install_pending_receipt(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "7" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            manifest = write_binary_generation(
                root,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "guard-pending-injection"},
            )
            validation = self.validation_result(manifest)
            validation_path = Path(validation["validation_result_path"])
            pending = {
                "schema": (
                    "java-upgrade-analyzer.active-binary-generation.v1"
                ),
                "result_generation_identity": manifest[
                    "result_generation_identity"
                ],
                "generation_directory": (
                    "binary_generations/"
                    f"{manifest['result_generation_identity']}"
                ),
                "validation_run_identity": validation[
                    "validation_run_identity"
                ],
                "validation_result_sha256": hashlib.sha256(
                    validation_path.read_bytes()
                ).hexdigest(),
                "activation_identity": activation,
                "activation_predecessor": None,
                "activation_state": "pending",
            }

            def injecting_guard():
                binary_output._write_active_descriptor(
                    root,
                    pending,
                    expect_missing=True,
                    relative_path=(
                        binary_output._PENDING_ACTIVE_DESCRIPTOR_RELATIVE_PATH
                    ),
                )

            with self.assertRaises(BinaryOutputError) as caught:
                activate_binary_generation(
                    root,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                    publication_guard=injecting_guard,
                )

            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_ACTIVE_GENERATION_DESCRIPTOR_CHANGED",
            )
            self.assertIsNone(binary_output.read_active_binary_generation(
                root, missing_ok=True
            ))
            self.assertEqual(
                binary_output.read_pending_binary_generation(root)[
                    "activation_identity"
                ],
                activation,
            )

    def test_active_lock_taxonomy_excludes_body_failures(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        body_failures = (
            TimeoutError("injected authority timeout"),
            OSError("injected authority I/O failure"),
        )
        for mode in ("direct", "deferred_publish"):
            for body_error in body_failures:
                with self.subTest(
                    mode=mode, error_type=type(body_error).__name__,
                ), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp).resolve()
                    manifest = write_binary_generation(
                        root,
                        decisions,
                        traces,
                        profile,
                        policy_identities={
                            "registry": f"{mode}-{type(body_error).__name__}"
                        },
                    )
                    validation = self.validation_result(manifest)
                    activation = hashlib.sha256(
                        f"{mode}-{type(body_error).__name__}".encode("utf-8")
                    ).hexdigest()
                    if mode == "deferred_publish":
                        activate_binary_generation(
                            root,
                            manifest,
                            validation_result=validation,
                            activation_identity=activation,
                            defer_publication=True,
                        )

                    def body_failure(error=body_error):
                        raise error

                    with self.assertRaises(type(body_error)) as body_caught:
                        if mode == "direct":
                            activate_binary_generation(
                                root,
                                manifest,
                                validation_result=validation,
                                activation_identity=activation,
                                publication_guard=body_failure,
                            )
                        else:
                            binary_output.publish_pending_binary_generation(
                                root,
                                expected_current_identity=manifest[
                                    "result_generation_identity"
                                ],
                                expected_activation_identity=activation,
                                publication_guard=body_failure,
                            )
                    self.assertIs(body_caught.exception, body_error)
                    self.assertIsNone(
                        binary_output.read_active_binary_generation(
                            root, missing_ok=True
                        )
                    )

        @contextmanager
        def acquisition_timeout(*_args, **_kwargs):
            raise TimeoutError("injected acquisition timeout")
            yield

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            manifest = write_binary_generation(
                root,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "acquisition"},
            )
            validation = self.validation_result(manifest)
            with patch.object(
                binary_output,
                "exclusive_file_lock",
                side_effect=acquisition_timeout,
            ), self.assertRaises(BinaryOutputError) as caught:
                activate_binary_generation(
                    root,
                    manifest,
                    validation_result=validation,
                )
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_ACTIVE_GENERATION_LOCK_TIMEOUT",
        )

    def test_active_lock_unavailable_taxonomy_covers_unsafe_inodes_and_enosys(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                target = root / "outside.lock"
                target.write_bytes(b"outside-lock\n")
                lock_path = root / ".active-generation.lock"
                try:
                    if kind == "symlink":
                        lock_path.symlink_to(target)
                    else:
                        os.link(target, lock_path)
                except OSError as error:
                    self.skipTest(f"{kind} unavailable: {error}")
                with self.assertRaises(BinaryOutputError) as caught:
                    compare_and_restore_active_binary_generation(
                        root,
                        expected_current_identity="a" * 64,
                        expected_activation_identity="b" * 64,
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_ACTIVE_GENERATION_LOCK_UNAVAILABLE",
                )
                self.assertEqual(target.read_bytes(), b"outside-lock\n")

        @contextmanager
        def acquisition_enosys(*_args, **_kwargs):
            raise OSError(errno.ENOSYS, "locking unavailable")
            yield

        with tempfile.TemporaryDirectory() as tmp, patch.object(
            binary_output,
            "exclusive_file_lock",
            side_effect=acquisition_enosys,
        ), self.assertRaises(BinaryOutputError) as caught:
            compare_and_restore_active_binary_generation(
                tmp,
                expected_current_identity="a" * 64,
                expected_activation_identity="b" * 64,
            )
        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_ACTIVE_GENERATION_LOCK_UNAVAILABLE",
        )

    def test_committed_activation_seal_makes_stale_rollback_token_unusable(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "c" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "sealed"},
            )
            activate_binary_generation(
                tmp,
                manifest,
                validation_result=self.validation_result(manifest),
                activation_identity=activation,
            )
            self.assertTrue(seal_active_binary_generation(
                tmp,
                expected_current_identity=manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            ))
            stale_rollback = compare_and_restore_active_binary_generation(
                tmp,
                expected_current_identity=manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=activation,
            )
            active = json.loads(
                (Path(tmp) / "active_binary_generation.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertFalse(stale_rollback)
        self.assertNotIn("activation_identity", active)
        self.assertNotIn("activation_predecessor", active)

    def test_activation_seal_reproves_sidecars_and_validation_before_commit(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "c" * 64
        for tamper_target in ("sidecar", "validation"):
            with self.subTest(tamper_target=tamper_target), tempfile.TemporaryDirectory() as tmp:
                manifest = write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": tamper_target},
                )
                validation = self.validation_result(manifest)
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )
                active_path = Path(tmp) / "active_binary_generation.json"
                receipt_bytes = active_path.read_bytes()
                if tamper_target == "sidecar":
                    target = (
                        Path(manifest["generation_directory"])
                        / "binary_summary.json"
                    )
                else:
                    target = Path(validation["validation_result_path"])
                target.write_bytes(target.read_bytes() + b"tampered")

                with self.assertRaises(BinaryOutputError) as caught:
                    seal_active_binary_generation(
                        tmp,
                        expected_current_identity=manifest[
                            "result_generation_identity"
                        ],
                        expected_activation_identity=activation,
                    )

                self.assertEqual(active_path.read_bytes(), receipt_bytes)
                self.assertIn(
                    "activation_identity",
                    json.loads(active_path.read_text(encoding="utf-8")),
                )
                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                )

    def test_direct_activation_and_same_context_seal_hash_generation_once(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "1" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "one-full-proof"},
            )
            validation = self.validation_result(manifest)
            with patch.object(
                binary_output,
                "_filesystem_supports_direct_seal_fast_path",
                return_value=True,
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                wraps=binary_output._verify_pending_generation_integrity,
            ) as verify:
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )
                self.assertEqual(verify.call_count, 1)
                self.assertTrue(seal_active_binary_generation(
                    tmp,
                    expected_current_identity=manifest[
                        "result_generation_identity"
                    ],
                    expected_activation_identity=activation,
                ))

            self.assertEqual(verify.call_count, 1)
            self.assertFalse(
                binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY
            )

    def test_direct_seal_missing_capability_falls_back_to_full_reproof(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "2" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "missing-capability"},
            )
            validation = self.validation_result(manifest)
            with patch.object(
                binary_output,
                "_filesystem_supports_direct_seal_fast_path",
                return_value=True,
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                wraps=binary_output._verify_pending_generation_integrity,
            ) as verify:
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )
                binary_output._discard_current_direct_seal_capability()
                self.assertTrue(seal_active_binary_generation(
                    tmp,
                    expected_current_identity=manifest[
                        "result_generation_identity"
                    ],
                    expected_activation_identity=activation,
                ))

            self.assertEqual(verify.call_count, 2)

    def test_direct_seal_probe_device_mismatch_forces_second_full_reproof(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "8" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "probe-device-mismatch"},
            )
            validation = self.validation_result(manifest)
            actual_device = os.lstat(tmp).st_dev
            with patch.object(
                binary_output,
                "_filesystem_supports_direct_seal_fast_path",
                return_value=True,
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                wraps=binary_output._verify_pending_generation_integrity,
            ) as verify:
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )
                binary_output._discard_current_direct_seal_capability()
                with patch.object(
                    binary_output,
                    "_prepare_post_guard_stat_recheck",
                    return_value=actual_device + 1,
                ):
                    self.assertTrue(seal_active_binary_generation(
                        tmp,
                        expected_current_identity=manifest[
                            "result_generation_identity"
                        ],
                        expected_activation_identity=activation,
                    ))

            self.assertEqual(verify.call_count, 3)

    def test_direct_seal_cross_thread_consumes_capability_and_full_reproves(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "3" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "cross-thread"},
            )
            validation = self.validation_result(manifest)
            with patch.object(
                binary_output,
                "_filesystem_supports_direct_seal_fast_path",
                return_value=True,
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                wraps=binary_output._verify_pending_generation_integrity,
            ) as verify:
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )
                with ThreadPoolExecutor(max_workers=1) as executor:
                    sealed = executor.submit(
                        seal_active_binary_generation,
                        tmp,
                        expected_current_identity=manifest[
                            "result_generation_identity"
                        ],
                        expected_activation_identity=activation,
                    ).result()

            self.assertTrue(sealed)
            self.assertEqual(verify.call_count, 2)
            self.assertFalse(
                binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY
            )

    def test_direct_seal_process_mismatch_and_fork_reset_force_full_reproof(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        for mode in ("pid-mismatch", "fork-reset"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                activation = hashlib.sha256(mode.encode("utf-8")).hexdigest()
                manifest = write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": mode},
                )
                validation = self.validation_result(manifest)
                with patch.object(
                    binary_output,
                    "_filesystem_supports_direct_seal_fast_path",
                    return_value=True,
                ), patch.object(
                    binary_output,
                    "_verify_pending_generation_integrity",
                    wraps=(
                        binary_output._verify_pending_generation_integrity
                    ),
                ) as verify:
                    activate_binary_generation(
                        tmp,
                        manifest,
                        validation_result=validation,
                        activation_identity=activation,
                    )
                    if mode == "fork-reset":
                        binary_output._reset_direct_seal_fast_path_after_fork()
                        seal_context = nullcontext()
                    else:
                        seal_context = patch.object(
                            binary_output.os,
                            "getpid",
                            return_value=os.getpid() + 1,
                        )
                    with seal_context:
                        self.assertTrue(seal_active_binary_generation(
                            tmp,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity=activation,
                        ))

                self.assertEqual(verify.call_count, 2)
                self.assertFalse(
                    binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY
                )

    def test_direct_seal_rejects_same_length_tamper_with_restored_mtime(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        for tamper_target in ("sidecar", "validation"):
            with self.subTest(tamper_target=tamper_target), tempfile.TemporaryDirectory() as tmp:
                activation = hashlib.sha256(
                    tamper_target.encode("utf-8")
                ).hexdigest()
                manifest = write_binary_generation(
                    tmp,
                    decisions,
                    traces,
                    profile,
                    policy_identities={"registry": f"ctime-{tamper_target}"},
                )
                validation = self.validation_result(manifest)
                with patch.object(
                    binary_output,
                    "_filesystem_supports_direct_seal_fast_path",
                    return_value=True,
                ), patch.object(
                    binary_output,
                    "_verify_pending_generation_integrity",
                    wraps=(
                        binary_output._verify_pending_generation_integrity
                    ),
                ) as verify:
                    activate_binary_generation(
                        tmp,
                        manifest,
                        validation_result=validation,
                        activation_identity=activation,
                    )
                    target = (
                        Path(manifest["generation_directory"])
                        / "binary_summary.json"
                        if tamper_target == "sidecar"
                        else Path(validation["validation_result_path"])
                    )
                    before = os.lstat(target)
                    content = bytearray(target.read_bytes())
                    content[len(content) // 2] ^= 1
                    with target.open("r+b") as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.utime(
                        target,
                        ns=(before.st_atime_ns, before.st_mtime_ns),
                        follow_symlinks=False,
                    )
                    after = os.lstat(target)
                    self.assertEqual(after.st_size, before.st_size)
                    self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)

                    with self.assertRaises(BinaryOutputError) as caught:
                        seal_active_binary_generation(
                            tmp,
                            expected_current_identity=manifest[
                                "result_generation_identity"
                            ],
                            expected_activation_identity=activation,
                        )

                self.assertEqual(
                    caught.exception.reason_code,
                    "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
                )
                self.assertEqual(verify.call_count, 2)
                self.assertFalse(
                    binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY
                )

    def test_direct_seal_rejects_same_size_replaced_sidecar(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "4" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "same-size-replace"},
            )
            validation = self.validation_result(manifest)
            with patch.object(
                binary_output,
                "_filesystem_supports_direct_seal_fast_path",
                return_value=True,
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                wraps=binary_output._verify_pending_generation_integrity,
            ) as verify:
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )
                target = (
                    Path(manifest["generation_directory"])
                    / "binary_summary.json"
                )
                before = os.lstat(target)
                replacement = target.with_name("replacement.tmp")
                content = bytearray(target.read_bytes())
                content[len(content) // 2] ^= 1
                replacement.write_bytes(content)
                os.utime(
                    replacement,
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                    follow_symlinks=False,
                )
                os.replace(replacement, target)
                self.assertEqual(os.lstat(target).st_size, before.st_size)
                self.assertNotEqual(os.lstat(target).st_ino, before.st_ino)

                with self.assertRaises(BinaryOutputError) as caught:
                    seal_active_binary_generation(
                        tmp,
                        expected_current_identity=manifest[
                            "result_generation_identity"
                        ],
                        expected_activation_identity=activation,
                    )

            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_PENDING_GENERATION_INTEGRITY_FAILED",
            )
            self.assertEqual(verify.call_count, 2)
            self.assertFalse(
                binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY
            )

    def test_direct_seal_wrong_operation_consumes_token_before_fallback(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "5" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "operation-replay"},
            )
            validation = self.validation_result(manifest)
            with patch.object(
                binary_output,
                "_filesystem_supports_direct_seal_fast_path",
                return_value=True,
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                wraps=binary_output._verify_pending_generation_integrity,
            ) as verify:
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )
                self.assertFalse(seal_active_binary_generation(
                    tmp,
                    expected_current_identity=manifest[
                        "result_generation_identity"
                    ],
                    expected_activation_identity="6" * 64,
                ))
                self.assertFalse(
                    binary_output._DIRECT_SEAL_FAST_PATH_REGISTRY
                )
                self.assertTrue(seal_active_binary_generation(
                    tmp,
                    expected_current_identity=manifest[
                        "result_generation_identity"
                    ],
                    expected_activation_identity=activation,
                ))

            self.assertEqual(verify.call_count, 2)

    def test_direct_seal_live_guard_is_last_check_before_descriptor_write(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        activation = "7" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "guard-last"},
            )
            validation = self.validation_result(manifest)
            with patch.object(
                binary_output,
                "_filesystem_supports_direct_seal_fast_path",
                return_value=True,
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                wraps=binary_output._verify_pending_generation_integrity,
            ) as verify:
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result=validation,
                    activation_identity=activation,
                )
                events = []
                real_write = binary_output._write_active_descriptor

                def observed_write(*args, **kwargs):
                    events.append("write")
                    return real_write(*args, **kwargs)

                def guard():
                    self.assertEqual(verify.call_count, 1)
                    events.append("guard")

                with patch.object(
                    binary_output,
                    "_write_active_descriptor",
                    side_effect=observed_write,
                ):
                    self.assertTrue(seal_active_binary_generation(
                        tmp,
                        expected_current_identity=manifest[
                            "result_generation_identity"
                        ],
                        expected_activation_identity=activation,
                        publication_guard=guard,
                    ))

            self.assertEqual(events, ["guard", "write"])
            self.assertEqual(verify.call_count, 1)

    def test_activation_seal_is_idempotent_across_equivalent_concurrent_runs(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        first_activation = "a" * 64
        second_activation = "b" * 64
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "concurrent-seal"},
            )
            validation = self.validation_result(manifest)
            activate_binary_generation(
                tmp,
                manifest,
                validation_result=validation,
                activation_identity=first_activation,
            )
            activate_binary_generation(
                tmp,
                manifest,
                validation_result=validation,
                activation_identity=second_activation,
            )

            # The second receipt supersedes the first, but its rollback target
            # is already the same immutable generation.  The first caller is
            # therefore durably successful without stealing the second
            # caller's receipt.
            self.assertTrue(seal_active_binary_generation(
                tmp,
                expected_current_identity=manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=first_activation,
            ))
            still_pending = json.loads(
                (Path(tmp) / "active_binary_generation.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                still_pending["activation_identity"], second_activation
            )
            self.assertEqual(
                still_pending["activation_predecessor"][
                    "result_generation_identity"
                ],
                manifest["result_generation_identity"],
            )

            self.assertTrue(seal_active_binary_generation(
                tmp,
                expected_current_identity=manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=second_activation,
            ))
            sealed_bytes = (
                Path(tmp) / "active_binary_generation.json"
            ).read_bytes()

            # A duplicate seal of the first receipt observes the exact same
            # committed state and succeeds without rewriting the descriptor.
            self.assertTrue(seal_active_binary_generation(
                tmp,
                expected_current_identity=manifest[
                    "result_generation_identity"
                ],
                expected_activation_identity=first_activation,
            ))
            self.assertEqual(
                (Path(tmp) / "active_binary_generation.json").read_bytes(),
                sealed_bytes,
            )

    def test_activation_seal_rejects_unsafe_superseding_receipt(self):
        generation = "a" * 64
        predecessor_generation = "0" * 64
        requested_activation = "b" * 64
        other_activation = "c" * 64
        descriptor = {
            "schema": "java-upgrade-analyzer.active-binary-generation.v1",
            "result_generation_identity": generation,
            "generation_directory": f"binary_generations/{generation}",
            "validation_run_identity": "d" * 64,
            "validation_result_sha256": "e" * 64,
            "activation_identity": other_activation,
            "activation_predecessor": {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": predecessor_generation,
                "generation_directory": (
                    f"binary_generations/{predecessor_generation}"
                ),
                "validation_run_identity": "f" * 64,
                "validation_result_sha256": "1" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            active_path = Path(tmp) / "active_binary_generation.json"
            active_path.write_text(json.dumps(descriptor), encoding="utf-8")
            before = active_path.read_bytes()

            self.assertFalse(seal_active_binary_generation(
                tmp,
                expected_current_identity=generation,
                expected_activation_identity=requested_activation,
            ))
            after = active_path.read_bytes()

            malformed_exact = dict(descriptor)
            malformed_exact["activation_identity"] = requested_activation
            malformed_exact.pop("activation_predecessor")
            active_path.write_text(
                json.dumps(malformed_exact), encoding="utf-8"
            )
            self.assertFalse(seal_active_binary_generation(
                tmp,
                expected_current_identity=generation,
                expected_activation_identity=requested_activation,
            ))

            malformed_sealed = dict(descriptor)
            malformed_sealed["activation_identity"] = None
            malformed_sealed.pop("activation_predecessor")
            active_path.write_text(
                json.dumps(malformed_sealed), encoding="utf-8"
            )
            self.assertFalse(seal_active_binary_generation(
                tmp,
                expected_current_identity=generation,
                expected_activation_identity=requested_activation,
            ))

        self.assertEqual(after, before)

    def test_generation_cannot_activate_without_independent_validation(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            with self.assertRaises(BinaryOutputError) as error:
                activate_binary_generation(tmp, manifest)
        self.assertEqual(
            error.exception.reason_code, "BINARY_GENERATION_VALIDATION_REQUIRED"
        )

    def test_activation_rejects_non_canonical_generation_identities(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            invalid_identities = (
                "",
                "/",
                "../" + manifest["result_generation_identity"],
                manifest["result_generation_identity"].upper(),
                "a" * 63,
                "g" * 64,
            )
            validation = self.validation_result(manifest)
            for identity in invalid_identities:
                with self.subTest(identity=identity):
                    invalid_manifest = dict(manifest)
                    invalid_manifest["result_generation_identity"] = identity
                    with self.assertRaises(BinaryOutputError) as error:
                        activate_binary_generation(tmp, invalid_manifest, validation_result={
                            **validation,
                            "result_generation_identity": identity,
                        })
                    self.assertEqual(
                        error.exception.reason_code,
                        "BINARY_GENERATION_ACTIVATION_TARGET_INVALID",
                    )
            self.assertFalse((Path(tmp) / "active_binary_generation.json").exists())

    def test_activation_rejects_generation_directory_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            generations = root / "binary_generations"
            generations.mkdir()
            external = root / "external-generation"
            external.mkdir()
            identity = "b" * 64
            try:
                (generations / identity).symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")
            manifest = {
                "schema": "java-upgrade-analyzer.binary-result-generation.v1",
                "result_generation_identity": identity,
                "analysis_context_identity": "context",
                "authority": "binary_first",
                "active_snapshot_identities": {},
                "trace_result_set_digest": "trace",
                "sidecar_content_identities": {},
                "policy_identities": {},
                "attachment_policy": "trace-results-bound-by-generation-attachment-v1",
            }

            with self.assertRaises(BinaryOutputError) as error:
                activate_binary_generation(tmp, manifest, validation_result={
                    "status": "passed",
                    "result_generation_identity": identity,
                    "validation_run_identity": "c" * 64,
                    "issue_count": 0,
                    "issues": [],
                })

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_ACTIVATION_TARGET_INVALID",
            )
            self.assertFalse((root / "active_binary_generation.json").exists())

    def test_deferred_activation_rejects_symlinked_observability_parent_without_escape(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "output"
            outside = Path(tmp) / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel.txt"
            sentinel.write_text("untouched", encoding="utf-8")
            manifest = write_binary_generation(
                root,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            try:
                (root / "binary_observability").symlink_to(
                    outside, target_is_directory=True
                )
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            with self.assertRaises(BinaryOutputError) as caught:
                activate_binary_generation(
                    root,
                    manifest,
                    validation_result=validation,
                    defer_publication=True,
                )

            self.assertEqual(
                caught.exception.reason_code,
                "BINARY_ACTIVE_GENERATION_DESCRIPTOR_INVALID",
            )
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")
            self.assertEqual(
                sorted(path.name for path in outside.iterdir()),
                ["sentinel.txt"],
            )

    def test_activation_rejects_unsafe_sidecar_names(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            generation = Path(manifest["generation_directory"])
            persisted = json.loads(
                (generation / "result_generation.json").read_text(encoding="utf-8")
            )
            validation = self.validation_result(manifest)
            digest = next(iter(manifest["sidecar_content_identities"].values()))
            for unsafe_name in (".", "..", "nested/file", "nested\\file", "/tmp/file"):
                with self.subTest(name=unsafe_name):
                    unsafe_manifest = dict(manifest)
                    unsafe_manifest["sidecar_content_identities"] = {
                        unsafe_name: digest,
                    }
                    unsafe_persisted = dict(persisted)
                    unsafe_persisted["sidecar_content_identities"] = {
                        unsafe_name: digest,
                    }
                    (generation / "result_generation.json").write_text(
                        json.dumps(unsafe_persisted), encoding="utf-8"
                    )

                    with self.assertRaises(BinaryOutputError) as error:
                        activate_binary_generation(
                            tmp, unsafe_manifest, validation_result=validation
                        )

                    self.assertEqual(
                        error.exception.reason_code,
                        "BINARY_GENERATION_ACTIVATION_INTEGRITY_FAILED",
                    )
            self.assertFalse((Path(tmp) / "active_binary_generation.json").exists())

    def test_activation_requires_persisted_manifest_identity_fields_to_match(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            conflicting_manifest = dict(manifest)
            conflicting_manifest["policy_identities"] = {"registry": "v2"}
            validation = self.validation_result(manifest)

            with self.assertRaises(BinaryOutputError) as error:
                activate_binary_generation(
                    tmp, conflicting_manifest, validation_result=validation
                )

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_ACTIVATION_MANIFEST_MISMATCH",
            )
            self.assertFalse((Path(tmp) / "active_binary_generation.json").exists())

    def test_activation_recomputes_generation_identity_from_manifest_payload(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            generation = Path(manifest["generation_directory"])
            tampered = dict(manifest)
            tampered["policy_identities"] = {"registry": "v2"}
            persisted = json.loads(
                (generation / "result_generation.json").read_text(encoding="utf-8")
            )
            persisted["policy_identities"] = {"registry": "v2"}
            (generation / "result_generation.json").write_text(
                json.dumps(persisted), encoding="utf-8"
            )

            with self.assertRaises(BinaryOutputError) as error:
                activate_binary_generation(tmp, tampered, validation_result=validation)

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_ACTIVATION_MANIFEST_MISMATCH",
            )
            self.assertFalse((Path(tmp) / "active_binary_generation.json").exists())

    def test_activation_rejects_unknown_generation_manifest_schema(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            generation = Path(manifest["generation_directory"])
            tampered = dict(manifest)
            tampered["schema"] = "attacker.invalid.v999"
            persisted = json.loads(
                (generation / "result_generation.json").read_text(encoding="utf-8")
            )
            persisted["schema"] = "attacker.invalid.v999"
            (generation / "result_generation.json").write_text(
                json.dumps(persisted), encoding="utf-8"
            )
            validation = self.validation_result(tampered)

            with self.assertRaises(BinaryOutputError) as error:
                activate_binary_generation(
                    tmp, tampered, validation_result=validation
                )

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_ACTIVATION_MANIFEST_MISMATCH",
            )
            self.assertFalse((Path(tmp) / "active_binary_generation.json").exists())

    def test_activation_rejects_nonempty_or_unpersisted_validation_result(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(
                manifest,
                issues=[{"reason_code": "ORACLE_FAILURE"}],
            )
            with self.assertRaises(BinaryOutputError) as issue_error:
                activate_binary_generation(tmp, manifest, validation_result=validation)
            self.assertEqual(
                issue_error.exception.reason_code,
                "BINARY_GENERATION_VALIDATION_REQUIRED",
            )

            clean_validation = self.validation_result(manifest)
            invalid_identity_validation = dict(clean_validation)
            invalid_identity_validation["validation_run_identity"] = "validation-1"
            with self.assertRaises(BinaryOutputError) as identity_error:
                activate_binary_generation(
                    tmp, manifest, validation_result=invalid_identity_validation
                )
            self.assertEqual(
                identity_error.exception.reason_code,
                "BINARY_GENERATION_VALIDATION_REQUIRED",
            )
            Path(clean_validation["validation_result_path"]).write_text(
                "{}\n", encoding="utf-8"
            )
            with self.assertRaises(BinaryOutputError) as attachment_error:
                activate_binary_generation(
                    tmp, manifest, validation_result=clean_validation
                )
            self.assertEqual(
                attachment_error.exception.reason_code,
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
            )
            self.assertFalse((Path(tmp) / "active_binary_generation.json").exists())

    def test_activation_rejects_minimal_or_self_inconsistent_validation_contract(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation_dir = Path(manifest["generation_directory"]) / "validation"
            validation_dir.mkdir(exist_ok=True)
            minimal_identity = "c" * 64
            minimal = {
                "validation_run_identity": minimal_identity,
                "result_generation_identity": manifest[
                    "result_generation_identity"
                ],
                "status": "passed",
                "issue_count": 0,
                "issues": [],
            }
            minimal_path = validation_dir / f"{minimal_identity}.json"
            minimal_path.write_text(json.dumps(minimal), encoding="utf-8")

            with self.assertRaises(BinaryOutputError) as minimal_error:
                activate_binary_generation(
                    tmp,
                    manifest,
                    validation_result={
                        **minimal,
                        "validation_result_path": str(minimal_path),
                    },
                )
            self.assertEqual(
                minimal_error.exception.reason_code,
                "BINARY_GENERATION_VALIDATION_REQUIRED",
            )

            inconsistent_results = (
                self.validation_result(manifest, issue_set_identity="a" * 64),
                self.validation_result(manifest, validation_run_identity="a" * 64),
            )
            for validation in inconsistent_results:
                with self.subTest(
                    validation_identity=validation["validation_run_identity"]
                ):
                    with self.assertRaises(BinaryOutputError) as identity_error:
                        activate_binary_generation(
                            tmp, manifest, validation_result=validation
                        )
                    self.assertEqual(
                        identity_error.exception.reason_code,
                        "BINARY_GENERATION_VALIDATION_REQUIRED",
                    )
            self.assertFalse((Path(tmp) / "active_binary_generation.json").exists())

    def test_activation_compares_persisted_validation_with_json_types(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            validation_path = Path(validation["validation_result_path"])
            persisted = json.loads(validation_path.read_text(encoding="utf-8"))
            persisted["issue_count"] = 0.0
            validation_path.write_text(
                json.dumps(
                    persisted,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ) + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(BinaryOutputError) as error:
                activate_binary_generation(
                    tmp, manifest, validation_result=validation
                )

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
            )
            self.assertFalse((Path(tmp) / "active_binary_generation.json").exists())

    def test_activation_rejects_symlinked_validation_attachment(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            validation_path = Path(validation["validation_result_path"])
            external = Path(tmp) / "external-validation.json"
            validation_path.replace(external)
            try:
                validation_path.symlink_to(external)
            except OSError as error:
                self.skipTest(f"file symlinks are unavailable: {error}")

            with self.assertRaises(BinaryOutputError) as activation_error:
                activate_binary_generation(
                    tmp, manifest, validation_result=validation
                )

            self.assertEqual(
                activation_error.exception.reason_code,
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
            )
            self.assertFalse((Path(tmp) / "active_binary_generation.json").exists())

    def test_report_loader_rejects_validation_attachment_sha_change(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            self._activate_sealed(output, manifest, validation)
            self.assertEqual(
                load_validated_generation(report)["validation"]["status"], "passed"
            )
            validation_path = Path(validation["validation_result_path"])
            validation_path.write_bytes(validation_path.read_bytes() + b" ")

            with self.assertRaises(BinaryReportError) as error:
                load_validated_generation(report)

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INTEGRITY_FAILED",
            )

    def test_report_loader_rejects_unknown_active_generation_schema(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            active_path = self._activate_sealed(
                output, manifest, validation
            )
            active = json.loads(active_path.read_text(encoding="utf-8"))
            active["schema"] = "attacker.invalid.active.v999"
            active_path.write_text(
                json.dumps(active, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(BinaryReportError) as error:
                load_validated_generation(report)

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_ACTIVE_GENERATION_INVALID",
            )

    def test_report_loader_rejects_unknown_result_generation_schema(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            self._activate_sealed(output, manifest, validation)
            manifest_path = (
                Path(manifest["generation_directory"]) / "result_generation.json"
            )
            persisted = json.loads(manifest_path.read_text(encoding="utf-8"))
            persisted["schema"] = "attacker.invalid.generation.v999"
            manifest_path.write_text(
                json.dumps(persisted, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(BinaryReportError) as error:
                load_validated_generation(report)

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_MANIFEST_MISMATCH",
            )

    def test_report_loader_accepts_validated_generation_without_performance_authority(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "v1"},
                additional_sidecars={
                    "binary_phase_manifest.json": b"pipeline-fingerprint\n",
                },
            )
            validation = self.validation_result(manifest)
            self._write_test_sealed_active_descriptor(
                output, manifest, validation
            )

            self.assertEqual(
                load_validated_generation(report)[
                    "manifest"
                ]["result_generation_identity"],
                manifest["result_generation_identity"],
            )

    def test_report_loader_classifies_symlinked_manifest_as_generation_damage(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            self._activate_sealed(output, manifest, validation)
            manifest_path = (
                Path(manifest["generation_directory"])
                / "result_generation.json"
            )
            outside = Path(tmp) / "manifest-target.json"
            outside.write_bytes(manifest_path.read_bytes())
            manifest_path.unlink()
            manifest_path.symlink_to(outside)

            with self.assertRaises(BinaryReportError) as error:
                load_validated_generation(report)

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_MANIFEST_MISMATCH",
            )

    def test_report_loader_classifies_nonregular_authority_as_authority_damage(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        binding = {
            "schema": "java-upgrade-analyzer.performance-authority-binding.v2",
            "authority_mode": "release_evidence",
            "support_contract_identity": "1" * 64,
            "evidence_sha256": "2" * 64,
            "source_implementation_identity": "3" * 64,
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
                "authority_mode": binding["authority_mode"],
            },
            schema_version="1",
        )
        authority = {
            "schema": "java-upgrade-analyzer.binary-publication-authority.v1",
            "authority_mode": "release_evidence",
            "binding_identity": binding["binding_identity"],
            "public_activation_allowed": True,
            "performance_authority_gate_binding": binding,
        }
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output,
                decisions,
                traces,
                profile,
                policy_identities={"registry": "v1"},
                additional_sidecars={
                    "binary_publication_authority.json": (
                        binary_output._json_bytes(authority)
                    ),
                },
            )
            validation = self.validation_result(manifest)
            self._write_test_sealed_active_descriptor(
                output, manifest, validation
            )
            authority_path = (
                Path(manifest["generation_directory"])
                / "binary_publication_authority.json"
            )
            authority_path.unlink()
            authority_path.mkdir()

            with self.assertRaises(BinaryReportError) as error:
                load_validated_generation(report)

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_PUBLICATION_AUTHORITY_INVALID",
            )

    def test_report_loader_rejects_unknown_validation_result_schema(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            active_path = self._activate_sealed(
                output, manifest, validation
            )
            validation_path = Path(validation["validation_result_path"])
            persisted = json.loads(validation_path.read_text(encoding="utf-8"))
            persisted["schema"] = "attacker.invalid.validation.v999"
            validation_path.write_text(
                json.dumps(persisted, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            active = json.loads(active_path.read_text(encoding="utf-8"))
            active["validation_result_sha256"] = hashlib.sha256(
                validation_path.read_bytes()
            ).hexdigest()
            active_path.write_text(
                json.dumps(active, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(BinaryReportError) as error:
                load_validated_generation(report)

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
            )

    def test_report_loader_rejects_minimal_passed_validation_attachment(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            active_path = self._activate_sealed(
                output, manifest, validation
            )
            validation_path = Path(validation["validation_result_path"])
            minimal = {
                "schema": "java-upgrade-analyzer.binary-validation-result.v1",
                "validation_run_identity": validation[
                    "validation_run_identity"
                ],
                "result_generation_identity": manifest[
                    "result_generation_identity"
                ],
                "status": "passed",
                "issue_count": 0,
                "issues": [],
            }
            validation_path.write_text(
                json.dumps(minimal, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            active = json.loads(active_path.read_text(encoding="utf-8"))
            active["validation_result_sha256"] = hashlib.sha256(
                validation_path.read_bytes()
            ).hexdigest()
            active_path.write_text(
                json.dumps(active, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(BinaryReportError) as error:
                load_validated_generation(report)

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_VALIDATION_ATTACHMENT_INVALID",
            )

    def test_report_loader_rejects_undeclared_optional_source_sidecars(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        for name, payload in (
            (
                "binary_source_explanations.json",
                {
                    "authority": "forged-unbound",
                    "declarations": [{"fake": True}],
                    "candidate_relationships": [],
                },
            ),
            (
                "binary_source_attestation.json",
                {"coverage_gaps": [], "language_file_counts": {"java": 999}},
            ),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                report = Path(tmp) / "report"
                output = report / ".runtime" / "binary_authority"
                manifest = write_binary_generation(
                    output, decisions, traces, profile,
                    policy_identities={"registry": "v1"},
                )
                validation = self.validation_result(manifest)
                self._activate_sealed(output, manifest, validation)
                self.assertNotIn(
                    name, manifest["sidecar_content_identities"]
                )
                injected = Path(manifest["generation_directory"]) / name
                injected.write_text(json.dumps(payload), encoding="utf-8")

                with self.assertRaises(BinaryReportError) as error:
                    load_validated_generation(report)

                self.assertEqual(
                    error.exception.reason_code,
                    "BINARY_GENERATION_UNDECLARED_SIDECAR",
                )

    def test_report_loader_accepts_declared_optional_source_sidecars(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        explanations = {
            "authority": "source_overlay",
            "declarations": [{"class_name": "demo/Api"}],
            "candidate_relationships": [],
        }
        attestation = {
            "coverage_gaps": [],
            "language_file_counts": {"java": 1},
        }
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output, decisions, traces, profile,
                policy_identities={"registry": "v1"},
                additional_sidecars={
                    "binary_source_explanations.json": json.dumps(
                        explanations
                    ).encode("utf-8"),
                    "binary_source_attestation.json": json.dumps(
                        attestation
                    ).encode("utf-8"),
                },
            )
            validation = self.validation_result(manifest)
            self._activate_sealed(output, manifest, validation)

            loaded = load_validated_generation(report)

        self.assertEqual(loaded["source_explanations"], explanations)
        self.assertEqual(loaded["source_attestation"], attestation)

    def test_report_loader_recomputes_generation_identity_after_activation(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report"
            output = report / ".runtime" / "binary_authority"
            manifest = write_binary_generation(
                output, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            validation = self.validation_result(manifest)
            self._activate_sealed(output, manifest, validation)
            manifest_path = (
                Path(manifest["generation_directory"])
                / "result_generation.json"
            )
            tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
            tampered["policy_identities"] = {"registry": "v2"}
            manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

            with self.assertRaises(BinaryReportError) as error:
                load_validated_generation(report)

            self.assertEqual(
                error.exception.reason_code,
                "BINARY_GENERATION_MANIFEST_MISMATCH",
            )


if __name__ == "__main__":
    unittest.main()
