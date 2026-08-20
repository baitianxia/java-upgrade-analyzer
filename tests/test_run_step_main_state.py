import csv
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import run_step  # noqa: E402
import path_runtime  # noqa: E402
import binary_output  # noqa: E402
import binary_report  # noqa: E402
import binary_pipeline  # noqa: E402
from tests import test_binary_output as binary_output_fixtures  # noqa: E402


class RunStepMainStateTest(unittest.TestCase):
    def _performance_authority_binding(
        self, marker="1", authority_mode="release_evidence"
    ):
        payload = {
            "schema": (
                "java-upgrade-analyzer.performance-authority-binding.v2"
            ),
            "authority_mode": authority_mode,
            "support_contract_identity": marker * 64,
            "evidence_sha256": "2" * 64,
            "source_implementation_identity": "3" * 64,
        }
        payload["binding_identity"] = binary_pipeline._identity(
            "binary_performance_authority_binding_identity",
            {
                key: payload[key]
                for key in (
                    "support_contract_identity",
                    "evidence_sha256",
                    "source_implementation_identity",
                    "authority_mode",
                )
            },
        )
        return payload

    def _write_release_authorized_generation(self, binary_root, marker="1"):
        """Create the minimal immutable authority bytes needed by seal tests."""

        root = Path(binary_root).resolve()
        performance_binding = self._performance_authority_binding(marker)
        publication_authority = {
            "schema": (
                "java-upgrade-analyzer.binary-publication-authority.v1"
            ),
            "authority_mode": "release_evidence",
            "binding_identity": performance_binding["binding_identity"],
            "public_activation_allowed": True,
            "performance_authority_gate_binding": performance_binding,
        }
        publication_bytes = binary_output._json_bytes(
            publication_authority
        )
        sidecar_identities = {
            name: marker * 64
            for name in binary_output._REQUIRED_CORE_GENERATION_SIDECARS
        }
        sidecar_identities["binary_publication_authority.json"] = (
            hashlib.sha256(publication_bytes).hexdigest()
        )
        manifest = {
            "schema": "java-upgrade-analyzer.binary-result-generation.v1",
            "analysis_context_identity": marker * 64,
            "authority": "binary_first",
            "active_snapshot_identities": {
                layer: marker * 64
                for layer in binary_output._RESULT_GENERATION_SNAPSHOT_LAYERS
            },
            "trace_result_set_digest": marker * 64,
            "sidecar_content_identities": sidecar_identities,
            "policy_identities": {},
            "attachment_policy": binary_output._GENERATION_ATTACHMENT_POLICY,
        }
        generation_identity = (
            binary_output._result_generation_identity_from_manifest(manifest)
        )
        self.assertRegex(generation_identity, r"^[0-9a-f]{64}$")
        manifest["result_generation_identity"] = generation_identity
        generation = root / "binary_generations" / generation_identity
        generation.mkdir(parents=True)
        (generation / "binary_publication_authority.json").write_bytes(
            publication_bytes
        )
        (generation / "result_generation.json").write_bytes(
            binary_output._json_bytes(manifest)
        )
        return generation_identity

    def _write_bound_step4_checkpoint(
        self,
        report,
        *,
        generation,
        validation,
        activation,
        performance_binding,
        validation_sha256="d" * 64,
        analysis_context="1" * 64,
    ):
        checkpoint = {
            "schema": (
                "java-upgrade-analyzer."
                "binary-generation-validation-checkpoint.v3"
            ),
            "status": (
                "independent_validation_passed_pending_activation"
            ),
            "result_generation_identity": generation,
            "analysis_context_identity": analysis_context,
            "validation_run_identity": validation,
            "validation_result_sha256": validation_sha256,
            "activation_identity": activation,
            "performance_authority_gate_binding": dict(
                performance_binding
            ),
        }
        checkpoint["checkpoint_content_identity"] = (
            binary_pipeline._resume_checkpoint_content_identity(checkpoint)
        )
        run_step.write_json(
            run_step._step4_validation_checkpoint_path(report), checkpoint
        )
        return checkpoint

    def _write_fake_step4_pipeline_result(
        self,
        script_args,
        *,
        generation="a" * 64,
        validation="b" * 64,
        validation_sha256="d" * 64,
        activation="c" * 64,
        phase_timings=None,
    ):
        output_root = Path(
            script_args[script_args.index("--output-root") + 1]
        )
        result_path = Path(
            script_args[script_args.index("--result-json") + 1]
        )
        performance_binding = self._performance_authority_binding()
        predecessor = run_step.read_active_binary_generation(
            output_root, missing_ok=True
        ) if output_root.exists() else None
        pending_path = (
            output_root
            / "binary_observability"
            / "pending_active_binary_generation.json"
        )
        run_step.write_json(pending_path, {
            "schema": "java-upgrade-analyzer.active-binary-generation.v1",
            "result_generation_identity": generation,
            "generation_directory": f"binary_generations/{generation}",
            "validation_run_identity": validation,
            "validation_result_sha256": validation_sha256,
            "activation_identity": activation,
            "activation_predecessor": predecessor,
            "activation_state": "pending",
        })
        self._write_bound_step4_checkpoint(
            output_root.parent.parent,
            generation=generation,
            validation=validation,
            activation=activation,
            performance_binding=performance_binding,
            validation_sha256=validation_sha256,
        )
        result = {
            "schema": "java-upgrade-analyzer.binary-pipeline-result.v1",
            "validation_status": "passed",
            "result_generation_identity": generation,
            "analysis_context_identity": "1" * 64,
            "validation_run_identity": validation,
            "activation_identity": activation,
            "activation_predecessor": predecessor,
            "activation_candidate_private": True,
            "active_generation_descriptor": str(pending_path),
            "performance_authority_gate_binding": performance_binding,
            "validation_checkpoint_retained": True,
            "validation_checkpoint_path": str(
                run_step._step4_validation_checkpoint_path(
                    output_root.parent.parent
                )
            ),
        }
        if phase_timings is not None:
            result["phase_timings"] = list(phase_timings)
        run_step.write_json(result_path, result)

    def _fake_step4_report_result(self, report_dir):
        report = Path(report_dir).resolve()
        active = run_step._read_step4_active_descriptor(report)
        generation = active["result_generation_identity"]
        destinations = run_step._step4_report_publication_destinations(report)
        transaction = binary_report._stage_directory_group(
            (
                (
                    destinations[0],
                    lambda stage, _prepared: run_step.write_json(
                        stage / "summary.json",
                        {"result_generation_identity": generation},
                    ),
                ),
                (
                    destinations[1],
                    lambda stage, _prepared: (
                        stage / "marker"
                    ).write_text("source", encoding="utf-8"),
                ),
            ),
            retain_transaction=True,
            transaction_binding={
                "result_generation_identity": generation,
                "validation_run_identity": active["validation_run_identity"],
                "validation_result_sha256": active[
                    "validation_result_sha256"
                ],
                "activation_identity": active["activation_identity"],
            },
        )
        return {
            "phase": "step4",
            "publication_transaction": transaction,
        }

    def _write_fake_step4_report_result(self, script_args):
        """Compatibility helper for tests that exercise the old CLI shape."""

        report = Path(
            script_args[script_args.index("--report-dir") + 1]
        ).resolve()
        result_path = Path(
            script_args[script_args.index("--result-json") + 1]
        )
        run_step.write_json(
            result_path, self._fake_step4_report_result(report)
        )

    def _git_source_repository(self, root):
        repository = Path(root) / "dependency-source"
        source = repository / "src" / "main" / "java" / "demo" / "Api.java"
        source.parent.mkdir(parents=True)
        source.write_text("package demo; public class Api {}\n", encoding="utf-8")
        commands = (
            ["git", "init", str(repository)],
            ["git", "-C", str(repository), "config", "user.name", "Test"],
            ["git", "-C", str(repository), "config", "user.email", "test@example.invalid"],
            ["git", "-C", str(repository), "add", "."],
            ["git", "-C", str(repository), "commit", "-m", "fixture"],
        )
        for command in commands:
            completed = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        commit = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        return repository, source.parent.parent, commit

    def test_main_runs_worktree_recovery_before_step0_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            report = root / ".upgrade-report"
            project.mkdir()
            events = []
            original_prepare = run_step.prepare_step0_context

            def recover(*args, **kwargs):
                events.append("recover")
                return {"removed_count": 0}

            def prepare(run_context, project_dir, **kwargs):
                events.append("step0")
                return original_prepare(run_context, project_dir, **kwargs)

            with patch.object(
                run_step,
                "recover_worktrees_before_execution",
                side_effect=recover,
            ) as recovery, patch.object(
                run_step,
                "prepare_step0_context",
                side_effect=prepare,
            ):
                exit_code = run_step.main(
                    [
                        "--step", "step0",
                        "--project-dir", str(project),
                        "--report-dir", str(report),
                    ],
                    _skip_environment_contract=True,
                )

        self.assertEqual(exit_code, run_step.EXIT_AWAITING_USER)
        recovery.assert_called_once()
        self.assertLess(events.index("recover"), events.index("step0"))

    def test_startup_recovery_removes_real_interrupted_worktree_and_writes_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository, _source_root, commit = self._git_source_repository(root)
            report = root / ".upgrade-report"
            worktree_root = root / "worktrees"
            worktree = path_runtime.create_detached_worktree(
                commit,
                repository,
                preferred_root=worktree_root,
            )
            lease = path_runtime._worktree_lease_path(worktree)
            payload = json.loads(lease.read_text(encoding="utf-8"))
            payload.update({"pid": 999_999_999, "process_start_token": "dead"})
            lease.write_text(json.dumps(payload), encoding="utf-8")
            args = SimpleNamespace(
                application_source=str(repository),
                dependency_source_dirs=[],
            )

            recovery = run_step.recover_worktrees_before_execution(
                repository,
                report,
                args,
                {},
                run_step.new_main_state(report),
            )
            audit = json.loads(
                run_step.worktree_recovery_path(report).read_text(encoding="utf-8")
            )

        self.assertEqual(recovery["status"], "passed")
        self.assertEqual(recovery["removed_count"], 1)
        self.assertEqual(audit["removed_count"], 1)
        self.assertFalse(worktree.exists())
        self.assertFalse(lease.exists())

    def test_dependency_source_git_materialization_pins_resolved_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository, _source_root, commit = self._git_source_repository(root)
            report = root / ".upgrade-report"

            result = run_step.materialize_dependency_source_git_url(
                repository.as_uri(), report, clone_timeout=30
            )
            metadata = json.loads(
                Path(result["metadata_path"]).read_text(encoding="utf-8")
            )

        self.assertEqual(result["resolved_commit"], commit)
        self.assertEqual(metadata["resolved_commit"], commit)
        self.assertTrue(result["repo_path"].endswith("/repository"))

    def test_dependency_source_mapping_carries_git_revision_into_binary_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository, source_root, commit = self._git_source_repository(root)
            config = root / "binary.json"
            config.write_text(json.dumps({
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
            }), encoding="utf-8")
            resolved_path = run_step._resolved_binary_pipeline_config_path(
                {
                    "binary_pipeline_config": str(config),
                    "dependency_source_mappings": [
                        f"com.example:demo={source_root}"
                    ],
                    "dependency_source_git_materializations": [{
                        "repo_path": str(repository),
                        "resolved_commit": commit,
                    }],
                },
                root,
                root / ".upgrade-report",
            )
            resolved = json.loads(resolved_path.read_text(encoding="utf-8"))

        source_set = resolved["source_overlay"]["source_sets"][0]
        self.assertEqual(source_set["owner_coord"], "com.example:demo")
        self.assertEqual(source_set["snapshot_revision"], commit)
        self.assertEqual(
            resolved["source_inputs"]["dependencies"]["status"], "available"
        )

    def test_orchestrator_exposes_no_engine_selection_or_fallback_api(self):
        self.assertFalse(hasattr(run_step, "normalize_binary_engine_mode"))
        self.assertFalse(hasattr(run_step, "validate_binary_engine_mode_transition"))
        self.assertFalse(hasattr(run_step, "ENGINE_DESCRIPTOR_RELATIVE_PATH"))

    def test_step4_config_source_overlay_is_direct_user_provision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "binary.json"
            config.write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                    "source_overlay": {
                        "source_sets": [{
                            "source_dirs": ["/must-not-be-read"],
                            "owner_type": "business",
                            "owner_coord": "business",
                        }],
                    },
                }),
                encoding="utf-8",
            )
            resolved_path = run_step._resolved_binary_pipeline_config_path(
                {"binary_pipeline_config": str(config)},
                root,
                root / ".upgrade-report",
            )
            resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
            self.assertEqual(
                resolved["source_inputs"]["business"]["status"], "available"
            )

    def test_step4_materializes_binary_config_from_step1_when_not_supplied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            automatic = {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "base": {"artifacts": []},
                "current": {"artifacts": []},
            }
            with patch.object(
                run_step,
                "materialize_binary_pipeline_config",
                return_value=automatic,
            ) as materialize:
                resolved_path = run_step._resolved_binary_pipeline_config_path(
                    {},
                    root,
                    report,
                )

            resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
            materialize.assert_called_once()
            self.assertEqual(resolved["base"], automatic["base"])
            self.assertEqual(
                resolved["source_inputs"]["business"]["status"], "not_provided"
            )
            self.assertEqual(
                resolved["source_inputs"]["dependencies"]["status"], "not_provided"
            )
            self.assertTrue(
                (report / ".runtime/state/binary_pipeline_config.materialized.json")
                .is_file()
            )

    def test_step4_materializer_receives_all_runtime_jvm_override_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            runtime_overrides = {
                "resolved_configuration_properties": {
                    "shared.feature": "enabled"
                },
                "base_resolved_configuration_properties": {
                    "side.feature": "base"
                },
                "current_resolved_configuration_properties": {
                    "side.feature": "current"
                },
                "jvm_system_properties": {"jdk.util.jar.version": "17"},
                "runtime_system_properties": {
                    "jdk.util.jar.enableMultiRelease": "true"
                },
                "jvm_arguments": ["-Djdk.util.jar.version=17"],
                "runtime_jvm_arguments": "-Xmx256m",
                "base_jvm_system_properties": {"base": "jvm"},
                "current_jvm_system_properties": {"current": "jvm"},
                "base_runtime_system_properties": {"base": "runtime"},
                "current_runtime_system_properties": {"current": "runtime"},
                "base_jvm_arguments": ["-Dbase.jvm=true"],
                "current_jvm_arguments": ["-Dcurrent.jvm=true"],
                "base_runtime_jvm_arguments": "-Dbase.runtime=true",
                "current_runtime_jvm_arguments": "-Dcurrent.runtime=true",
            }
            automatic = {
                "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                "base": {"artifacts": []},
                "current": {"artifacts": []},
            }
            with patch.object(
                run_step,
                "materialize_binary_pipeline_config",
                return_value=automatic,
            ) as materialize:
                run_step._binary_pipeline_config_path(
                    runtime_overrides, root, report
                )

            passed = materialize.call_args.kwargs["runtime_overrides"]

        self.assertEqual(passed, runtime_overrides)

    def test_step4_config_without_source_records_missing_source_categories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "binary.json"
            config.write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                }),
                encoding="utf-8",
            )
            resolved_path = run_step._resolved_binary_pipeline_config_path(
                {"binary_pipeline_config": str(config)},
                root,
                root / ".upgrade-report",
            )
            resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
            self.assertEqual(
                resolved["source_inputs"],
                {
                    "purpose_version": "source-input-purpose-v3",
                    "business": {"status": "not_provided", "origin": "not_provided"},
                    "dependencies": {"status": "not_provided", "origin": "not_provided"},
                },
            )

    def test_step2_has_no_fixed_user_interaction(self):
        manifest = json.loads(
            (ROOT_DIR / "scripts" / "step_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        step2 = next(item for item in manifest["steps"] if item["id"] == "step2")
        self.assertIsNone(step2["interaction"])
        self.assertTrue(step2["auto_continue_on_success"])

    def test_new_protocol_rejects_old_unified_source_fields(self):
        with self.assertRaisesRegex(run_step.StepError, "当前不支持"):
            run_step.normalize_intent_patch({
                "action": "continue",
                "set": {"source_locations": ["/old/source"]},
            })
        with self.assertRaisesRegex(run_step.StepError, "当前不支持"):
            run_step.normalize_intent_patch({
                "action": "continue",
                "set": {"source_provision_choice": "provide"},
            })

    def test_checkout_build_source_is_automatic_when_no_more_source_is_provided(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            source_dir = root / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            config = root / "binary.json"
            config.write_text(
                json.dumps({
                    "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
                }),
                encoding="utf-8",
            )

            resolved_path = run_step._resolved_binary_pipeline_config_path(
                {
                    "binary_pipeline_config": str(config),
                    "analysis_mode": "checkout_build",
                    "base_branch": "main",
                    "current_branch": "upgrade",
                    "source_dirs": [str(source_dir)],
                    "source_dirs_status": "auto_detected",
                    "target_module": "app",
                },
                root,
                report,
            )
            resolved = json.loads(resolved_path.read_text(encoding="utf-8"))

        self.assertEqual(
            resolved["source_overlay"]["source_sets"][0]["owner_type"],
            "business",
        )
        self.assertEqual(
            resolved["source_inputs"]["business"],
            {"status": "available", "origin": "checkout_build"},
        )
        self.assertEqual(
            resolved["source_inputs"]["dependencies"]["status"],
            "not_provided",
        )

    def test_binary_failure_preserves_previous_outputs_and_records_internal_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            s4_dir = report / "evidence" / "api_changes"
            s4_dir.mkdir(parents=True)
            sentinel = s4_dir / "previous-complete.txt"
            sentinel.write_text("preserve", encoding="utf-8")
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")
            progress = (
                report / ".runtime" / "binary_authority"
                / "binary_observability" / "latest_in_progress.json"
            )
            progress.parent.mkdir(parents=True)
            progress.write_text(json.dumps({
                "current_phase": "independent_validation",
                "last_completed_phase": "immutable_generation_write",
            }), encoding="utf-8")
            log = report / ".runtime" / "background" / "run.log"
            log.parent.mkdir(parents=True)
            log.write_text("traceback detail\n", encoding="utf-8")
            def fail_current_pipeline(*_args, **_kwargs):
                progress.write_text(json.dumps({
                    "current_phase": "independent_validation",
                    "last_completed_phase": "immutable_generation_write",
                    "attempt": "current",
                }), encoding="utf-8")
                raise run_step.StepError(
                    "parser failed",
                    reason_codes=["ORACLE_FAILED"],
                    diagnostic={"traceback": "line 1"},
                )

            with patch.object(
                run_step, "run_python", side_effect=fail_current_pipeline,
            ):
                with self.assertRaisesRegex(
                    run_step.StepError, "BINARY_GENERATION_FAILED"
                ):
                    run_step._run_binary_step4(
                        run_context={
                            "binary_pipeline_config": str(config),
                        },
                        project_dir=root,
                        report_dir=report,
                        s4_dir=s4_dir,
                    )
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")
            failures = list(
                (report / ".runtime" / "binary_authority" / "binary_failures").glob("*.json")
            )
            self.assertEqual(len(failures), 1)
            failure = json.loads(failures[0].read_text())
            self.assertTrue(failure["fail_closed"])
            self.assertEqual(failure["failed_phase"], "independent_validation")
            self.assertEqual(failure["diagnostic"]["traceback"], "line 1")
            self.assertEqual(failure["traceback"], "line 1")
            self.assertIn("traceback detail", failure["run_log_tail"])
            self.assertIn("ORACLE_FAILED", failure["failure_reason_codes"])
            latest_failure = json.loads((
                report
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / "binary_observability"
                / "latest_failure.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(
                latest_failure["binary_failure_identity"],
                failure["binary_failure_identity"],
            )

    def test_step4_pre_pipeline_failure_ignores_stale_phase_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            progress = (
                report / ".runtime" / "binary_authority"
                / "binary_observability" / "latest_in_progress.json"
            )
            progress.parent.mkdir(parents=True)
            progress.write_text(json.dumps({
                "current_phase": "validated_generation_activation",
                "last_completed_phase": "independent_validation",
                "attempt": "previous",
            }), encoding="utf-8")

            with self.assertRaisesRegex(
                run_step.StepError, "BINARY_GENERATION_FAILED"
            ):
                run_step._run_binary_step4(
                    run_context={
                        "binary_pipeline_config": str(root / "missing.json"),
                    },
                    project_dir=root,
                    report_dir=report,
                    s4_dir=report / "evidence" / "api_changes",
                )

            failures = list(
                (report / ".runtime" / "binary_authority" / "binary_failures")
                .glob("*.json")
            )
            self.assertEqual(len(failures), 1)
            failure = json.loads(failures[0].read_text(encoding="utf-8"))

        self.assertEqual(failure["failed_phase"], "")
        self.assertEqual(failure["last_progress"], {})

    def test_step4_parent_recovers_stderr_failure_without_borrowing_writer_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")
            progress = (
                report / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / "binary_observability" / "latest_in_progress.json"
            )
            public_failure = {
                "schema": (
                    "java-upgrade-analyzer.binary-pipeline-failure.v1"
                ),
                "status": "failed",
                "reason_code": "BINARY_PIPELINE_CONFIG_SCHEMA_INVALID",
                "failure_type": "BinaryPipelineError",
                "detail": "invalid config",
                "cause": None,
                "failed_phase": "",
                "last_progress": {},
                "attempt_identity": "a" * 64,
                "progress_bound_to_attempt": False,
                "core_transaction_status": "failed",
                "core_transaction_succeeded": False,
                "core_result_receipt": None,
                "fail_closed": True,
            }

            def fail_and_publish_competitor_progress(_cmd, **_kwargs):
                progress.parent.mkdir(parents=True, exist_ok=True)
                progress.write_text(json.dumps({
                    "schema": "java-upgrade-analyzer.binary-progress.v1",
                    "attempt_identity": "f" * 64,
                    "status": "running",
                    "current_phase": "validated_generation_activation",
                }), encoding="utf-8")
                return "", json.dumps(public_failure) + "\n", 1

            with patch.object(
                run_step,
                "run_cmd",
                side_effect=fail_and_publish_competitor_progress,
            ), patch.object(run_step, "print_output"):
                with self.assertRaises(run_step.StepError) as caught:
                    run_step._run_binary_step4(
                        run_context={
                            "binary_pipeline_config": str(config),
                        },
                        project_dir=root,
                        report_dir=report,
                        s4_dir=run_step.step4_api_changes_dir(report),
                    )
            failure_paths = list((
                report / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / "binary_failures"
            ).glob("*.json"))
            self.assertEqual(len(failure_paths), 1)
            failure = json.loads(
                failure_paths[0].read_text(encoding="utf-8")
            )

        self.assertIn(
            "BINARY_PIPELINE_CONFIG_SCHEMA_INVALID",
            caught.exception.reason_codes,
        )
        self.assertIn("BINARY_GENERATION_FAILED", caught.exception.reason_codes)
        self.assertEqual(failure["failed_phase"], "")
        self.assertEqual(failure["last_progress"], {})
        structured = failure["diagnostic"]["structured_result"]
        self.assertEqual(structured["core_transaction_status"], "failed")
        self.assertEqual(structured["attempt_identity"], "a" * 64)

    def test_binary_failure_record_uses_only_attempt_bound_child_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            progress_path = (
                report / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / "binary_observability" / "latest_in_progress.json"
            )
            progress_path.parent.mkdir(parents=True)
            progress_path.write_text(json.dumps({
                "attempt_identity": "f" * 64,
                "current_phase": "validated_generation_activation",
            }), encoding="utf-8")
            child_progress = {
                "attempt_identity": "a" * 64,
                "status": "running",
                "current_phase": "independent_validation",
            }
            child_failure = {
                "schema": (
                    "java-upgrade-analyzer.binary-pipeline-failure.v1"
                ),
                "status": "failed",
                "reason_code": "BINARY_INDEPENDENT_VALIDATION_FAILED",
                "failure_type": "BinaryPipelineError",
                "detail": "oracle mismatch",
                "cause": None,
                "failed_phase": "independent_validation",
                "last_progress": child_progress,
                "attempt_identity": "a" * 64,
                "progress_bound_to_attempt": True,
                "core_transaction_status": "failed",
                "core_transaction_succeeded": False,
                "core_result_receipt": None,
                "fail_closed": True,
            }
            error = run_step.StepError(
                "pipeline failed",
                reason_codes=["BINARY_INDEPENDENT_VALIDATION_FAILED"],
                diagnostic={"structured_result": child_failure},
            )

            failure, _path = run_step._record_binary_failure(
                report,
                "config.json",
                error,
                progress_baseline=None,
            )

        self.assertEqual(failure["last_progress"], child_progress)
        self.assertEqual(failure["failed_phase"], "independent_validation")

    def test_step4_runs_only_pipeline_as_child_and_prepares_report_in_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            s4_dir = report / "evidence" / "api_changes"
            s4_dir.mkdir(parents=True)
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")
            calls = []

            def fake_run(script_name, script_args, _cwd, **_kwargs):
                calls.append((script_name, list(script_args)))
                self.assertEqual(script_name, "binary_pipeline.py")
                self._write_fake_step4_pipeline_result(
                    script_args,
                    phase_timings=[{
                        "phase": "binary_trace",
                        "elapsed_seconds": 0.125,
                        "formal_trace_result_count": 1,
                    }],
                )

            def prepare_report(**kwargs):
                self.assertEqual(kwargs["phase"], "step4")
                self.assertEqual(
                    Path(kwargs["report_dir"]).resolve(), report.resolve()
                )
                return self._fake_step4_report_result(report)

            with patch.object(
                run_step, "run_python", side_effect=fake_run
            ), patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                side_effect=prepare_report,
            ) as prepare:
                result = run_step._run_binary_step4(
                    run_context={
                        "binary_pipeline_config": str(config),
                    },
                    project_dir=root,
                    report_dir=report,
                    s4_dir=s4_dir,
                )
            self.assertEqual(result["result_generation_identity"], "a" * 64)
            self.assertEqual(
                [item[0] for item in calls],
                ["binary_pipeline.py"],
            )
            prepare.assert_called_once()
            pipeline_args = calls[0][1]
            self.assertIn("--retain-validation-checkpoint", pipeline_args)
            resolved_config_path = Path(
                pipeline_args[pipeline_args.index("--config") + 1]
            )
            resolved_config = json.loads(resolved_config_path.read_text())
            self.assertEqual(
                resolved_config["source_inputs"],
                {
                    "purpose_version": "source-input-purpose-v3",
                    "business": {"status": "not_provided", "origin": "not_provided"},
                    "dependencies": {"status": "not_provided", "origin": "not_provided"},
                },
            )
            self.assertNotIn("source_overlay", resolved_config)
            timing_path = report / ".runtime/observability/step4_timing.csv"
            self.assertTrue(timing_path.read_bytes().startswith(b"\xef\xbb\xbf"))
            with timing_path.open(encoding="utf-8-sig", newline="") as handle:
                timings = list(csv.DictReader(handle))
            self.assertEqual(timings[0]["phase"], "binary_trace")
            self.assertEqual(
                timings[0]["result_generation_identity"], "a" * 64
            )
            self.assertEqual(
                timings[-1]["phase"], "step4_human_report_publication"
            )

    def test_step4_timing_write_failure_does_not_rollback_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")

            def fake_run(_script_name, script_args, _cwd, **_kwargs):
                self._write_fake_step4_pipeline_result(script_args)

            with patch.object(
                run_step, "run_python", side_effect=fake_run
            ), patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                side_effect=lambda **_kwargs: (
                    self._fake_step4_report_result(report)
                ),
            ), patch.object(
                run_step,
                "write_csv_rows",
                side_effect=OSError("metrics unavailable"),
            ), patch.object(
                run_step, "_record_binary_failure"
            ) as record_failure:
                result = run_step._run_binary_step4(
                    run_context={"binary_pipeline_config": str(config)},
                    project_dir=root,
                    report_dir=report,
                    s4_dir=report / "evidence" / "api_changes",
                )

        self.assertEqual(result["result_generation_identity"], "a" * 64)
        record_failure.assert_not_called()

    def test_in_process_report_prepare_requires_workflow_lock_and_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            output = report / "evidence" / "api_changes"
            calls = []

            def trusted_prepare(
                report_dir,
                output_dir,
                *,
                candidate_activation_identity="",
            ):
                binary_report._consume_report_publication_prepare_capability(
                    report_dir, "step4"
                )
                calls.append(
                    (
                        Path(report_dir).resolve(),
                        Path(output_dir).resolve(),
                        candidate_activation_identity,
                    )
                )
                return {"phase": "step4", "trusted": True}

            with patch.object(
                run_step,
                "prepare_step4_publication_candidate",
                side_effect=trusted_prepare,
            ) as prepare:
                with self.assertRaises(run_step.StepError) as unlocked:
                    run_step._prepare_binary_report_publication_candidate_in_process(
                        phase="step4",
                        report_dir=report,
                        output_dir=output,
                        candidate_activation_identity="a" * 64,
                    )
                self.assertIn(
                    "BINARY_REPORT_PREPARE_WORKFLOW_LOCK_REQUIRED",
                    unlocked.exception.reason_codes,
                )
                prepare.assert_not_called()

                with run_step._workflow_mutation_lock(
                    report, timeout_seconds=0.1
                ):
                    with self.assertRaises(run_step.StepError) as wrong_root:
                        run_step._prepare_binary_report_publication_candidate_in_process(
                            phase="step4",
                            report_dir=report.parent / "other-report",
                            output_dir=(
                                report.parent
                                / "other-report"
                                / "evidence"
                                / "api_changes"
                            ),
                            candidate_activation_identity="a" * 64,
                        )
                    self.assertIn(
                        "BINARY_REPORT_PREPARE_WORKFLOW_LOCK_REQUIRED",
                        wrong_root.exception.reason_codes,
                    )
                    prepare.assert_not_called()
                    result = (
                        run_step._prepare_binary_report_publication_candidate_in_process(
                            phase="step4",
                            report_dir=report,
                            output_dir=output,
                            candidate_activation_identity="a" * 64,
                        )
                    )

            self.assertEqual(result, {"phase": "step4", "trusted": True})
            self.assertEqual(
                calls,
                [(report, output.resolve(), "a" * 64)],
            )

    def test_in_process_report_prepare_dispatches_step5_and_step6_under_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            step5_output = report / "evidence" / "call_chain"
            findings = report / ".runtime" / "findings" / "s6_findings.json"
            deliverable = report / "deliverables" / "report.md"
            calls = []

            def prepare_step5(
                report_dir,
                output_dir,
                *,
                selected_coords=(),
                selected_names=(),
            ):
                binary_report._consume_report_publication_prepare_capability(
                    report_dir, "step5"
                )
                calls.append(
                    (
                        "step5",
                        Path(output_dir),
                        tuple(selected_coords),
                        tuple(selected_names),
                    )
                )
                return {"phase": "step5"}

            def prepare_step6(report_dir, output_findings, output_report):
                binary_report._consume_report_publication_prepare_capability(
                    report_dir, "step6"
                )
                calls.append(
                    (
                        "step6",
                        Path(output_findings),
                        Path(output_report),
                    )
                )
                return {"phase": "step6"}

            with patch.object(
                run_step,
                "prepare_step5_publication_candidate",
                side_effect=prepare_step5,
            ), patch.object(
                run_step,
                "prepare_step6_publication_candidate",
                side_effect=prepare_step6,
            ), run_step._workflow_mutation_lock(
                report, timeout_seconds=0.1
            ):
                step5 = (
                    run_step._prepare_binary_report_publication_candidate_in_process(
                        phase="step5",
                        report_dir=report,
                        output_dir=step5_output,
                        selected_coords=("com.example:demo",),
                        selected_names=("demo",),
                    )
                )
                step6 = (
                    run_step._prepare_binary_report_publication_candidate_in_process(
                        phase="step6",
                        report_dir=report,
                        output_findings=findings,
                        output_report=deliverable,
                    )
                )

            self.assertEqual(step5, {"phase": "step5"})
            self.assertEqual(step6, {"phase": "step6"})
            self.assertEqual(
                calls,
                [
                    (
                        "step5",
                        step5_output,
                        ("com.example:demo",),
                        ("demo",),
                    ),
                    ("step6", findings, deliverable),
                ],
            )

    def test_step4_deferred_handoff_writer_lock_covers_complete_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")
            state = {"held": False}
            events = []

            @contextmanager
            def tracked_writer_lock(path, *, timeout_seconds):
                self.assertEqual(
                    Path(path).name, ".binary-pipeline-run.lock"
                )
                self.assertEqual(
                    timeout_seconds,
                    run_step._STEP4_DEFERRED_HANDOFF_LOCK_TIMEOUT_SECONDS,
                )
                self.assertFalse(state["held"])
                events.append("writer_lock_enter")
                state["held"] = True
                try:
                    yield Path(path)
                finally:
                    state["held"] = False
                    events.append("writer_lock_exit")

            def fake_run(script_name, script_args, _cwd, **_kwargs):
                self.assertEqual(script_name, "binary_pipeline.py")
                self.assertFalse(state["held"])
                events.append("pipeline_child")
                self._write_fake_step4_pipeline_result(script_args)

            def prepare_report(**kwargs):
                self.assertTrue(state["held"])
                events.append("report_candidate")
                return self._fake_step4_report_result(kwargs["report_dir"])

            def locked_phase(name, value=None):
                def invoke(*_args, **_kwargs):
                    self.assertTrue(state["held"], name)
                    events.append(name)
                    return value
                return invoke

            original_revalidate = (
                run_step._revalidate_binary_step4_deferred_handoff
            )

            def revalidate(*args, **kwargs):
                self.assertTrue(state["held"], "revalidate_handoff")
                events.append("revalidate_handoff")
                return original_revalidate(*args, **kwargs)

            def finalize(*_args, delete_checkpoint=True, **_kwargs):
                name = (
                    "delete_checkpoint"
                    if delete_checkpoint
                    else "validate_checkpoint"
                )
                self.assertTrue(state["held"], name)
                events.append(name)
                return True

            with patch.object(
                run_step,
                "exclusive_file_lock",
                side_effect=tracked_writer_lock,
            ), patch.object(
                run_step, "run_python", side_effect=fake_run
            ), patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                side_effect=prepare_report,
            ), patch.object(
                run_step,
                "_revalidate_binary_step4_deferred_handoff",
                side_effect=revalidate,
            ), patch.object(
                run_step, "run_gate", side_effect=locked_phase("gate")
            ), patch.object(
                run_step,
                "mark_report_publication_gate_passed",
                side_effect=locked_phase(
                    "mark_gate", {"gate_receipt_identity": "receipt-1"}
                ),
            ), patch.object(
                run_step,
                "publish_report_publication",
                side_effect=locked_phase("publish_reports", True),
            ), patch.object(
                run_step,
                "_seal_binary_step4_activation",
                side_effect=locked_phase("publish_activation", True),
            ), patch.object(
                run_step,
                "_finalize_binary_step4_transaction",
                side_effect=finalize,
            ), patch.object(
                run_step,
                "_commit_binary_step4_activation_receipt",
                side_effect=locked_phase("commit_activation", True),
            ), patch.object(
                run_step,
                "commit_report_publication",
                side_effect=locked_phase("commit_reports", True),
            ), patch.object(
                run_step,
                "reconcile_current_release",
                side_effect=locked_phase(
                    "reconcile_release",
                    {
                        "step4": {"status": "current"},
                        "step5": {"status": "stale"},
                        "step6": {"status": "stale"},
                    },
                ),
            ):
                result = run_step._run_binary_step4(
                    run_context={"binary_pipeline_config": str(config)},
                    project_dir=root,
                    report_dir=report,
                    s4_dir=run_step.step4_api_changes_dir(report),
                    complete_deferred_handoff=True,
                    gate_name="jar_compare",
                    strict_risk_gate=False,
                )

        self.assertEqual(result["result_generation_identity"], "a" * 64)
        self.assertFalse(state["held"])
        self.assertEqual(events, [
            "pipeline_child",
            "writer_lock_enter",
            "revalidate_handoff",
            "report_candidate",
            "gate",
            "mark_gate",
            "publish_reports",
            "publish_activation",
            "validate_checkpoint",
            "commit_activation",
            "delete_checkpoint",
            "commit_reports",
            "reconcile_release",
            "writer_lock_exit",
        ])

    def test_step4_deferred_handoff_revalidates_after_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")
            state = {"held": False}
            calls = []
            competitor_generation = "9" * 64
            competitor_validation = "8" * 64
            competitor_validation_sha256 = "7" * 64
            competitor_activation = "f" * 64

            @contextmanager
            def replace_candidate_before_handoff(path, *, timeout_seconds):
                self.assertFalse(state["held"])
                pending_path = (
                    report
                    / run_step.BINARY_OUTPUT_RELATIVE_PATH
                    / "binary_observability"
                    / "pending_active_binary_generation.json"
                )
                self._write_bound_step4_checkpoint(
                    report,
                    generation=competitor_generation,
                    validation=competitor_validation,
                    activation=competitor_activation,
                    performance_binding=self._performance_authority_binding(),
                    validation_sha256=competitor_validation_sha256,
                )
                run_step.write_json(pending_path, {
                    "schema": (
                        "java-upgrade-analyzer."
                        "active-binary-generation.v1"
                    ),
                    "result_generation_identity": competitor_generation,
                    "generation_directory": (
                        f"binary_generations/{competitor_generation}"
                    ),
                    "validation_run_identity": competitor_validation,
                    "validation_result_sha256": (
                        competitor_validation_sha256
                    ),
                    "activation_identity": competitor_activation,
                    "activation_predecessor": None,
                    "activation_state": "pending",
                })
                state["held"] = True
                try:
                    yield Path(path)
                finally:
                    state["held"] = False

            def fake_run(script_name, script_args, _cwd, **_kwargs):
                calls.append(script_name)
                self.assertEqual(script_name, "binary_pipeline.py")
                self._write_fake_step4_pipeline_result(script_args)

            def record_failure(*_args, **_kwargs):
                self.assertTrue(state["held"])
                return {}, report / "failure.json"

            with patch.object(
                run_step,
                "exclusive_file_lock",
                side_effect=replace_candidate_before_handoff,
            ), patch.object(
                run_step, "run_python", side_effect=fake_run
            ), patch.object(
                run_step,
                "_record_binary_failure",
                side_effect=record_failure,
            ):
                with self.assertRaises(run_step.StepError) as caught:
                    run_step._run_binary_step4(
                        run_context={
                            "binary_pipeline_config": str(config)
                        },
                        project_dir=root,
                        report_dir=report,
                        s4_dir=run_step.step4_api_changes_dir(report),
                    )
            remaining_pending = run_step.read_pending_binary_generation(
                report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            )
            remaining_checkpoint = run_step.read_json(
                run_step._step4_validation_checkpoint_path(report)
            )

        self.assertEqual(calls, ["binary_pipeline.py"])
        self.assertFalse(state["held"])
        self.assertEqual(
            remaining_pending["result_generation_identity"],
            competitor_generation,
        )
        self.assertEqual(
            remaining_pending["activation_identity"],
            competitor_activation,
        )
        self.assertEqual(
            remaining_checkpoint["result_generation_identity"],
            competitor_generation,
        )
        self.assertIn(
            "BINARY_STEP4_DEFERRED_HANDOFF_REVALIDATION_FAILED",
            caught.exception.reason_codes,
        )
        self.assertIn(
            "BINARY_GENERATION_FAILED", caught.exception.reason_codes
        )

    def test_step4_deferred_handoff_rejects_replaced_public_predecessor(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            result_path = (
                run_step.runtime_state_dir(report)
                / "binary_pipeline_result.json"
            )
            self._write_fake_step4_pipeline_result([
                "--output-root", str(binary_root),
                "--result-json", str(result_path),
            ])
            replacement_generation = "f" * 64
            run_step.write_json(
                binary_root / "active_binary_generation.json",
                {
                    "schema": (
                        "java-upgrade-analyzer."
                        "active-binary-generation.v1"
                    ),
                    "result_generation_identity": replacement_generation,
                    "generation_directory": (
                        f"binary_generations/{replacement_generation}"
                    ),
                    "validation_run_identity": "e" * 64,
                    "validation_result_sha256": "d" * 64,
                },
            )
            result = run_step.read_json(result_path)

            with run_step._binary_step4_deferred_handoff_lock(
                report, timeout_seconds=0.1
            ), self.assertRaises(run_step.StepError) as caught:
                run_step._revalidate_binary_step4_deferred_handoff(
                    report, result
                )

        self.assertIn(
            "BINARY_STEP4_DEFERRED_HANDOFF_REVALIDATION_FAILED",
            caught.exception.reason_codes,
        )

    def test_step4_deferred_handoff_binds_validation_sha_and_analysis_context(self):
        for mutation in ("validation_sha256", "analysis_context"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                report = Path(tmp).resolve() / ".upgrade-report"
                binary_root = (
                    report / run_step.BINARY_OUTPUT_RELATIVE_PATH
                )
                result_path = (
                    run_step.runtime_state_dir(report)
                    / "binary_pipeline_result.json"
                )
                self._write_fake_step4_pipeline_result([
                    "--output-root", str(binary_root),
                    "--result-json", str(result_path),
                ])
                result = run_step.read_json(result_path)
                if mutation == "validation_sha256":
                    pending_path = (
                        binary_root
                        / "binary_observability"
                        / "pending_active_binary_generation.json"
                    )
                    pending = run_step.read_json(pending_path)
                    pending["validation_result_sha256"] = "e" * 64
                    run_step.write_json(pending_path, pending)
                else:
                    result["analysis_context_identity"] = "e" * 64

                with run_step._binary_step4_deferred_handoff_lock(
                    report, timeout_seconds=0.1
                ), self.assertRaises(run_step.StepError) as caught:
                    run_step._revalidate_binary_step4_deferred_handoff(
                        report, result
                    )

            self.assertIn(
                "BINARY_STEP4_DEFERRED_HANDOFF_REVALIDATION_FAILED",
                caught.exception.reason_codes,
            )

    def test_step4_child_failure_never_adopts_live_checkpoint_for_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            generation = "9" * 64
            validation = "8" * 64
            validation_sha256 = "7" * 64
            activation = "6" * 64
            self._write_bound_step4_checkpoint(
                report,
                generation=generation,
                validation=validation,
                activation=activation,
                performance_binding=self._performance_authority_binding(),
                validation_sha256=validation_sha256,
            )
            run_step.write_json(
                binary_root
                / "binary_observability"
                / "pending_active_binary_generation.json",
                {
                    "schema": (
                        "java-upgrade-analyzer."
                        "active-binary-generation.v1"
                    ),
                    "result_generation_identity": generation,
                    "generation_directory": (
                        f"binary_generations/{generation}"
                    ),
                    "validation_run_identity": validation,
                    "validation_result_sha256": validation_sha256,
                    "activation_identity": activation,
                    "activation_predecessor": None,
                    "activation_state": "pending",
                },
            )

            with patch.object(
                run_step,
                "run_python",
                side_effect=run_step.StepError("child failed without receipt"),
            ), patch.object(
                run_step,
                "_record_binary_failure",
                return_value=({}, report / "failure.json"),
            ):
                with self.assertRaises(run_step.StepError) as caught:
                    run_step._run_binary_step4(
                        run_context={
                            "binary_pipeline_config": str(config)
                        },
                        project_dir=root,
                        report_dir=report,
                        s4_dir=run_step.step4_api_changes_dir(report),
                    )
            remaining_pending = run_step.read_pending_binary_generation(
                binary_root
            )
            remaining_checkpoint = run_step.read_json(
                run_step._step4_validation_checkpoint_path(report)
            )

        self.assertEqual(
            remaining_pending["activation_identity"], activation
        )
        self.assertEqual(
            remaining_checkpoint["activation_identity"], activation
        )
        self.assertEqual(
            caught.exception.diagnostic["active_generation_rollback"],
            "not_attempted_without_owned_receipt",
        )
        self.assertEqual(
            caught.exception.diagnostic["report_publication_rollback"],
            "not_attempted_without_owned_receipt",
        )

    def test_step4_deferred_handoff_releases_writer_lock_on_report_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")
            state = {"held": False}
            exits = []

            @contextmanager
            def tracked_writer_lock(path, *, timeout_seconds):
                state["held"] = True
                try:
                    yield Path(path)
                finally:
                    state["held"] = False
                    exits.append("released")

            def fake_run(script_name, script_args, _cwd, **_kwargs):
                self.assertEqual(script_name, "binary_pipeline.py")
                self.assertFalse(state["held"])
                self._write_fake_step4_pipeline_result(script_args)

            def fail_report_prepare(**_kwargs):
                self.assertTrue(state["held"])
                raise run_step.StepError("injected report failure")

            def record_failure(*_args, **_kwargs):
                self.assertTrue(state["held"])
                return {}, report / "failure.json"

            with patch.object(
                run_step,
                "exclusive_file_lock",
                side_effect=tracked_writer_lock,
            ), patch.object(
                run_step, "run_python", side_effect=fake_run
            ), patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                side_effect=fail_report_prepare,
            ), patch.object(
                run_step,
                "_record_binary_failure",
                side_effect=record_failure,
            ):
                with self.assertRaises(run_step.StepError):
                    run_step._run_binary_step4(
                        run_context={
                            "binary_pipeline_config": str(config)
                        },
                        project_dir=root,
                        report_dir=report,
                        s4_dir=run_step.step4_api_changes_dir(report),
                    )

        self.assertFalse(state["held"])
        self.assertEqual(exits, ["released"])

    def test_step4_deferred_handoff_lock_timeout_does_not_mutate_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")
            calls = []

            class LockTimeout:
                def __enter__(self):
                    raise TimeoutError("writer busy")

                def __exit__(self, *_args):
                    self.fail("unacquired lock must not be released")

            def fake_run(script_name, script_args, _cwd, **_kwargs):
                calls.append(script_name)
                self.assertEqual(script_name, "binary_pipeline.py")
                self._write_fake_step4_pipeline_result(script_args)

            with patch.object(
                run_step,
                "exclusive_file_lock",
                return_value=LockTimeout(),
            ), patch.object(
                run_step, "run_python", side_effect=fake_run
            ), patch.object(
                run_step, "_rollback_binary_step4_transaction"
            ) as rollback, patch.object(
                run_step, "_record_binary_failure"
            ) as record_failure:
                with self.assertRaises(run_step.StepError) as caught:
                    run_step._run_binary_step4(
                        run_context={
                            "binary_pipeline_config": str(config)
                        },
                        project_dir=root,
                        report_dir=report,
                        s4_dir=run_step.step4_api_changes_dir(report),
                    )

        self.assertEqual(calls, ["binary_pipeline.py"])
        self.assertIn(
            "BINARY_STEP4_DEFERRED_HANDOFF_LOCK_TIMEOUT",
            caught.exception.reason_codes,
        )
        rollback.assert_not_called()
        record_failure.assert_not_called()

    def test_step4_deferred_handoff_contends_with_pipeline_writer_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            lock_path = (
                report
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / ".binary-pipeline-run.lock"
            )
            with run_step.exclusive_file_lock(
                lock_path, timeout_seconds=1.0
            ):
                with self.assertRaises(run_step.StepError) as caught:
                    with run_step._binary_step4_deferred_handoff_lock(
                        report, timeout_seconds=0.01
                    ):
                        self.fail("competing handoff acquired writer lock")
            with run_step._binary_step4_deferred_handoff_lock(
                report, timeout_seconds=0.1
            ) as acquired:
                self.assertEqual(Path(acquired), lock_path)

        self.assertIn(
            "BINARY_STEP4_DEFERRED_HANDOFF_LOCK_TIMEOUT",
            caught.exception.reason_codes,
        )

    def test_step4_recovery_waits_for_pipeline_writer_before_reading_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            writer_lock = (
                report
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / ".binary-pipeline-run.lock"
            )
            with run_step.exclusive_file_lock(
                writer_lock, timeout_seconds=1.0
            ), patch.object(
                run_step,
                "_STEP4_RECOVERY_WRITER_LOCK_TIMEOUT_SECONDS",
                0.01,
            ), patch.object(
                run_step, "_recover_binary_step4_transaction"
            ) as recover:
                with self.assertRaises(run_step.StepError) as caught:
                    with run_step._binary_step4_run_lock(
                        report, timeout_seconds=0.1
                    ):
                        self.fail("recovery ran without the writer lease")

        recover.assert_not_called()
        self.assertIn(
            "BINARY_STEP4_RECOVERY_WRITER_LOCK_TIMEOUT",
            caught.exception.reason_codes,
        )
        self.assertEqual(
            caught.exception.diagnostic.get("lock_path"), str(writer_lock)
        )

    def test_step4_recovery_releases_pipeline_writer_before_child_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            writer_lock = (
                report
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / ".binary-pipeline-run.lock"
            )
            events = []

            def recover(*_args, **_kwargs):
                events.append("recovery")
                with self.assertRaises(TimeoutError):
                    with run_step.exclusive_file_lock(
                        writer_lock, timeout_seconds=0.01
                    ):
                        self.fail("recovery did not hold the writer lease")

            with patch.object(
                run_step,
                "_recover_binary_step4_transaction",
                side_effect=recover,
            ):
                with run_step._binary_step4_run_lock(
                    report, timeout_seconds=0.1
                ):
                    events.append("child_scope")
                    with run_step.exclusive_file_lock(
                        writer_lock, timeout_seconds=0.1
                    ) as acquired:
                        self.assertEqual(Path(acquired), writer_lock)
                        events.append("child_writer_acquired")

        self.assertEqual(
            events,
            ["recovery", "child_scope", "child_writer_acquired"],
        )

    def test_step4_recovery_pipeline_writer_lock_isolated_by_output_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            blocked_report = root / "blocked" / ".upgrade-report"
            independent_report = root / "independent" / ".upgrade-report"
            blocked_writer = (
                blocked_report
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / ".binary-pipeline-run.lock"
            )
            independent_writer = (
                independent_report
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / ".binary-pipeline-run.lock"
            )
            recoveries = []

            with run_step.exclusive_file_lock(
                blocked_writer, timeout_seconds=1.0
            ), patch.object(
                run_step,
                "_recover_binary_step4_transaction",
                side_effect=lambda *_args, **_kwargs: recoveries.append(
                    "independent"
                ),
            ):
                with run_step._binary_step4_run_lock(
                    independent_report, timeout_seconds=0.1
                ):
                    with run_step.exclusive_file_lock(
                        independent_writer, timeout_seconds=0.1
                    ):
                        pass

        self.assertEqual(recoveries, ["independent"])

    def test_step4_recovery_rejects_unsafe_pipeline_writer_lock_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            writer_lock = (
                report
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / ".binary-pipeline-run.lock"
            )
            writer_lock.mkdir(parents=True)
            with patch.object(
                run_step, "_recover_binary_step4_transaction"
            ) as recover:
                with self.assertRaises(run_step.StepError) as caught:
                    with run_step._binary_step4_run_lock(
                        report, timeout_seconds=0.1
                    ):
                        self.fail("unsafe writer path was accepted")

        recover.assert_not_called()
        self.assertIn(
            "BINARY_STEP4_RECOVERY_WRITER_LOCK_UNAVAILABLE",
            caught.exception.reason_codes,
        )
        self.assertEqual(
            caught.exception.diagnostic.get("lock_path"), str(writer_lock)
        )

    def test_step4_main_startup_recovery_does_not_read_while_writer_is_busy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            writer_lock = (
                report
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / ".binary-pipeline-run.lock"
            )
            with run_step.exclusive_file_lock(
                writer_lock, timeout_seconds=1.0
            ), patch.object(
                run_step,
                "_STEP4_RECOVERY_WRITER_LOCK_TIMEOUT_SECONDS",
                0.01,
            ), patch.object(
                run_step, "_recover_binary_step4_transaction"
            ) as recover, patch.object(
                run_step, "_classify_step4_recovery_disposition"
            ) as classify, patch.object(
                run_step, "_apply_step4_startup_recovery"
            ) as apply_recovery:
                with self.assertRaises(run_step.StepError) as caught:
                    run_step._recover_and_apply_step4_startup_state(
                        args=SimpleNamespace(step="auto"),
                        main_state={},
                        report_dir=report,
                        project_dir=root,
                        manifest_steps={},
                        structured_user_response=None,
                        has_structured_response=False,
                        gate_name="binary_generation",
                        strict_risk_gate=False,
                    )

        recover.assert_not_called()
        classify.assert_not_called()
        apply_recovery.assert_not_called()
        self.assertIn(
            "BINARY_STEP4_RECOVERY_WRITER_LOCK_TIMEOUT",
            caught.exception.reason_codes,
        )

    def test_step4_main_startup_holds_both_locks_through_republish_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            step4_lock = binary_root / ".step4-run.lock"
            writer_lock = binary_root / ".binary-pipeline-run.lock"
            events = []

            def assert_startup_locks(phase):
                for lock_path in (step4_lock, writer_lock):
                    with self.assertRaises(TimeoutError):
                        with run_step.exclusive_file_lock(
                            lock_path, timeout_seconds=0.01
                        ):
                            self.fail(
                                f"{phase} did not retain {lock_path.name}"
                            )
                events.append(phase)

            def recover(*_args, **_kwargs):
                assert_startup_locks("recover")
                return "committed_receipt_requires_republication"

            def classify(*_args, **_kwargs):
                assert_startup_locks("classify")
                return {"action": run_step._STEP4_RELEASE_REPUBLISH}

            def apply_recovery(**_kwargs):
                assert_startup_locks("republish_apply")
                return {
                    "action": run_step._STEP4_RELEASE_REPUBLISH,
                    "applied": True,
                }

            with patch.object(
                run_step,
                "_recover_binary_step4_transaction",
                side_effect=recover,
            ), patch.object(
                run_step,
                "_classify_step4_recovery_disposition",
                side_effect=classify,
            ), patch.object(
                run_step,
                "_startup_step4_recovery_target_hint",
                return_value="step5",
            ), patch.object(
                run_step,
                "_apply_step4_startup_recovery",
                side_effect=apply_recovery,
            ):
                result = run_step._recover_and_apply_step4_startup_state(
                    args=SimpleNamespace(step="auto"),
                    main_state={},
                    report_dir=report,
                    project_dir=root,
                    manifest_steps={},
                    structured_user_response=None,
                    has_structured_response=False,
                    gate_name="binary_generation",
                    strict_risk_gate=False,
                )
            for lock_path in (step4_lock, writer_lock):
                with run_step.exclusive_file_lock(
                    lock_path, timeout_seconds=0.1
                ):
                    pass

        self.assertEqual(events, ["recover", "classify", "republish_apply"])
        self.assertEqual(
            result["disposition"],
            "committed_receipt_requires_republication",
        )
        self.assertEqual(result["target_hint"], "step5")

    def test_step4_main_startup_releases_both_locks_when_apply_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            lock_paths = (
                binary_root / ".step4-run.lock",
                binary_root / ".binary-pipeline-run.lock",
            )
            with patch.object(
                run_step,
                "_recover_binary_step4_transaction",
                return_value="nothing_to_recover",
            ), patch.object(
                run_step,
                "_classify_step4_recovery_disposition",
                return_value={"action": run_step._STEP4_RELEASE_CURRENT},
            ), patch.object(
                run_step,
                "_startup_step4_recovery_target_hint",
                return_value="step4",
            ), patch.object(
                run_step,
                "_apply_step4_startup_recovery",
                side_effect=run_step.StepError("injected startup failure"),
            ):
                with self.assertRaises(run_step.StepError):
                    run_step._recover_and_apply_step4_startup_state(
                        args=SimpleNamespace(step="auto"),
                        main_state={},
                        report_dir=report,
                        project_dir=root,
                        manifest_steps={},
                        structured_user_response=None,
                        has_structured_response=False,
                        gate_name="binary_generation",
                        strict_risk_gate=False,
                    )
            for lock_path in lock_paths:
                with run_step.exclusive_file_lock(
                    lock_path, timeout_seconds=0.1
                ):
                    pass

    def test_step4_run_lock_rejects_concurrent_execution_for_same_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            acquired = threading.Event()
            release = threading.Event()
            failures = []

            def hold_lock():
                with run_step._binary_step4_run_lock(
                    report, timeout_seconds=1
                ):
                    acquired.set()
                    release.wait(timeout=2)

            owner = threading.Thread(target=hold_lock)
            owner.start()
            self.assertTrue(acquired.wait(timeout=2))
            try:
                with self.assertRaises(run_step.StepError) as error:
                    with run_step._binary_step4_run_lock(
                        report, timeout_seconds=0.05
                    ):
                        failures.append("unexpected-acquire")
            finally:
                release.set()
                owner.join(timeout=2)

        self.assertFalse(owner.is_alive())
        self.assertFalse(failures)
        self.assertIn(
            "BINARY_STEP4_RUN_ALREADY_ACTIVE", error.exception.reason_codes
        )

    def test_workflow_mutation_lock_covers_state_reset_before_step_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            acquired = threading.Event()
            release = threading.Event()

            def hold_lock():
                with run_step._workflow_mutation_lock(
                    report, timeout_seconds=1
                ):
                    acquired.set()
                    release.wait(timeout=2)

            owner = threading.Thread(target=hold_lock)
            owner.start()
            self.assertTrue(acquired.wait(timeout=2))
            try:
                with self.assertRaises(run_step.StepError) as caught:
                    with run_step._workflow_mutation_lock(
                        report, timeout_seconds=0.05
                    ):
                        self.fail("concurrent workflow mutation lock acquired")
            finally:
                release.set()
                owner.join(timeout=2)

        self.assertFalse(owner.is_alive())
        self.assertIn(
            "WORKFLOW_MUTATION_ALREADY_ACTIVE", caught.exception.reason_codes
        )

    def test_workflow_mutation_lock_does_not_reclassify_body_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            with self.assertRaisesRegex(
                TimeoutError, "downstream operation timed out"
            ):
                with run_step._workflow_mutation_lock(
                    report, timeout_seconds=0.1
                ):
                    raise TimeoutError("downstream operation timed out")

            with run_step._workflow_mutation_lock(
                report, timeout_seconds=0.1
            ):
                self.assertTrue(
                    run_step._workflow_mutation_lock_is_held(report)
                )

    def test_step4_failure_rollback_does_not_clobber_newer_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            config = root / "binary.json"
            config.write_text("{}", encoding="utf-8")
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            binary_root.mkdir(parents=True)
            active_path = binary_root / "active_binary_generation.json"
            previous = self._write_release_authorized_generation(
                binary_root, marker="7"
            )
            attempted = self._write_release_authorized_generation(
                binary_root, marker="8"
            )
            newer = self._write_release_authorized_generation(
                binary_root, marker="9"
            )
            activation = "c" * 64
            predecessor = {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": previous,
                "generation_directory": f"binary_generations/{previous}",
                "validation_run_identity": "1" * 64,
                "validation_result_sha256": "2" * 64,
            }
            run_step.write_json(active_path, {
                **predecessor,
            })

            def fake_run(script_name, script_args, _cwd, **_kwargs):
                self.assertEqual(script_name, "binary_pipeline.py")
                self._write_fake_step4_pipeline_result(
                    script_args,
                    generation=attempted,
                    validation="3" * 64,
                    validation_sha256="4" * 64,
                    activation=activation,
                    phase_timings=[],
                )

            def fail_report_prepare(**_kwargs):
                run_step.write_json(active_path, {
                    "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                    "result_generation_identity": newer,
                    "generation_directory": f"binary_generations/{newer}",
                    "validation_run_identity": "5" * 64,
                    "validation_result_sha256": "6" * 64,
                    "activation_identity": "d" * 64,
                    "activation_predecessor": predecessor,
                })
                raise run_step.StepError("injected report failure")

            with patch.object(
                run_step, "run_python", side_effect=fake_run
            ), patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                side_effect=fail_report_prepare,
            ), patch.object(
                run_step,
                "_record_binary_failure",
                return_value=({}, report / "failure.json"),
            ):
                with self.assertRaises(run_step.StepError) as error:
                    run_step._run_binary_step4(
                        run_context={"binary_pipeline_config": str(config)},
                        project_dir=root,
                        report_dir=report,
                        s4_dir=report / "evidence" / "api_changes",
                    )
            final_active = run_step.read_json(active_path)

        self.assertEqual(final_active["result_generation_identity"], newer)
        self.assertEqual(
            error.exception.diagnostic["active_generation_rollback"],
            "skipped_active_generation_or_token_changed",
        )

    def test_committed_step4_checkpoint_cleanup_is_best_effort(self):
        with patch.object(
            run_step,
            "_delete_step4_validation_checkpoint_durable",
            side_effect=run_step.StepError("injected cleanup failure"),
        ):
            self.assertFalse(
                run_step._cleanup_committed_step4_checkpoint(Path("unused"))
            )

    def test_step4_transaction_finalizer_deletes_only_fully_bound_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            checkpoint = (
                binary_root
                / "binary_observability"
                / "validation_checkpoint.json"
            )
            checkpoint.parent.mkdir(parents=True)
            summary = run_step.step4_api_changes_dir(report) / "summary.json"
            generation = self._write_release_authorized_generation(
                binary_root, marker="a"
            )
            validation = "b" * 64
            activation = "c" * 64
            validation_sha256 = "d" * 64
            run_step.write_json(checkpoint, {
                "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
                "status": "independent_validation_passed_pending_activation",
                "result_generation_identity": generation,
                "validation_run_identity": validation,
                "activation_identity": activation,
            })
            run_step.write_json(binary_root / "active_binary_generation.json", {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": generation,
                "generation_directory": f"binary_generations/{generation}",
                "validation_run_identity": validation,
                "validation_result_sha256": validation_sha256,
                "activation_identity": activation,
                "activation_predecessor": None,
            })
            destinations = run_step._step4_report_publication_destinations(report)
            transaction = binary_report._stage_directory_group((
                (destinations[0], lambda stage, _prepared: run_step.write_json(
                    stage / "summary.json",
                    {"result_generation_identity": generation},
                )),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("source", encoding="utf-8")),
            ),
                retain_transaction=True,
                transaction_binding={
                    "result_generation_identity": generation,
                    "validation_run_identity": validation,
                    "validation_result_sha256": validation_sha256,
                    "activation_identity": activation,
                },
            )
            gate_receipt = binary_report.mark_report_publication_gate_passed(
                destinations,
                expected_transaction_id=transaction["transaction_id"],
                expected_binding=transaction["binding"],
                gate_name="jar_compare",
                strict_risk_gate=False,
            )
            binary_report.publish_report_publication(
                destinations,
                expected_transaction_id=transaction["transaction_id"],
                expected_binding=transaction["binding"],
            )
            result = {
                "validation_checkpoint_retained": True,
                "validation_checkpoint_path": str(checkpoint),
                "result_generation_identity": generation,
                "validation_run_identity": validation,
                "activation_identity": activation,
                "report_publication_transaction": transaction,
                "report_publication_gate_receipt": gate_receipt,
            }

            finalized = run_step._finalize_binary_step4_transaction(
                report, result
            )

        self.assertTrue(finalized)
        self.assertFalse(checkpoint.exists())

    def test_report_implementation_identity_is_static_diagnostic_metadata(self):
        original = binary_report.report_implementation_identity()
        changed_runtime = dict(
            binary_report._CAPTURED_REPORT_RUNTIME_IDENTITY
        )
        changed_runtime["platform"] += "-changed"
        with patch.object(
            binary_report, "_report_runtime_identity", return_value=changed_runtime
        ):
            self.assertEqual(
                binary_report.report_implementation_identity(), original
            )

    def test_report_implementation_metadata_does_not_affect_release_binding(self):
        loaded = {
            "manifest": {"result_generation_identity": "a" * 64},
            "active": {
                "validation_run_identity": "b" * 64,
                "validation_result_sha256": "c" * 64,
            },
        }
        binding = {
            "result_generation_identity": "a" * 64,
            "validation_run_identity": "b" * 64,
            "validation_result_sha256": "c" * 64,
            "report_implementation_identity": "d" * 64,
        }

        self.assertTrue(
            binary_report._step4_publication_binding_matches_loaded(
                binding, loaded
            )
        )

    def test_changed_report_implementation_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            destinations = (
                run_step._step4_report_publication_destinations(report)
            )
            transaction = binary_report._stage_directory_group((
                (destinations[0], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new-api", encoding="utf-8")),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new-source", encoding="utf-8")),
            ), retain_transaction=True)
            transaction_path, _group = (
                binary_report._publication_transaction_path(
                    [Path(item).resolve() for item in destinations]
                )
            )
            payload = run_step.read_json(transaction_path)
            current = payload["binding"]["report_implementation_identity"]
            payload["binding"]["report_implementation_identity"] = (
                "0" * 64 if current != "0" * 64 else "1" * 64
            )
            binary_report._atomic_json(transaction_path, payload)

            metadata = (
                binary_report.report_publication_transaction_recovery_metadata(
                    destinations
                )
            )
            receipt = binary_report.report_publication_transaction_receipt(
                destinations,
                expected_transaction_id=metadata["transaction_id"],
                expected_binding=metadata["binding"],
            )
            gate_receipt = binary_report.mark_report_publication_gate_passed(
                destinations,
                expected_transaction_id=metadata["transaction_id"],
                expected_binding=metadata["binding"],
                gate_name="jar_compare",
                strict_risk_gate=False,
            )
            binary_report.publish_report_publication(
                destinations,
                expected_transaction_id=metadata["transaction_id"],
                expected_binding=metadata["binding"],
            )
            cleanup_complete = binary_report.commit_report_publication(
                destinations,
                expected_transaction_id=metadata["transaction_id"],
                expected_binding=metadata["binding"],
            )

            self.assertEqual(metadata["implementation_status"], "mismatch")
            self.assertEqual(receipt["state"], "pending_gate")
            self.assertEqual(gate_receipt["gate_name"], "jar_compare")
            self.assertTrue(cleanup_complete)
            self.assertEqual(
                tuple(
                    (destination / "marker").read_text(encoding="utf-8")
                    for destination in destinations
                ),
                ("new-api", "new-source"),
            )

    def test_legacy_report_rollback_failure_never_reports_success(self):
        for transaction_kind in ("legacy_v2",):
            for state in ("pending_gate", "gate_passed"):
                for failed_layer in ("report", "active"):
                    with (
                        self.subTest(
                            kind=transaction_kind,
                            state=state,
                            failed_layer=failed_layer,
                        ),
                        tempfile.TemporaryDirectory() as tmp,
                    ):
                        report = Path(tmp).resolve() / ".upgrade-report"
                        destinations = (
                            run_step._step4_report_publication_destinations(
                                report
                            )
                        )
                        for destination, value in zip(
                            destinations, ("old-api", "old-source")
                        ):
                            destination.mkdir(parents=True)
                            (destination / "marker").write_text(
                                value, encoding="utf-8"
                            )
                        binary_root = (
                            report / run_step.BINARY_OUTPUT_RELATIVE_PATH
                        )
                        generation = self._write_release_authorized_generation(
                            binary_root, marker="b"
                        )
                        validation = "b" * 64
                        validation_sha256 = "c" * 64
                        activation = "d" * 64
                        active_path = (
                            binary_root / "active_binary_generation.json"
                        )
                        run_step.write_json(active_path, {
                            "schema": (
                                "java-upgrade-analyzer."
                                "active-binary-generation.v1"
                            ),
                            "result_generation_identity": generation,
                            "generation_directory": (
                                f"binary_generations/{generation}"
                            ),
                            "validation_run_identity": validation,
                            "validation_result_sha256": validation_sha256,
                            "activation_identity": activation,
                            "activation_predecessor": None,
                        })
                        transaction = binary_report._stage_directory_group((
                            (destinations[0], lambda stage, _prepared: (
                                stage / "marker"
                            ).write_text("new-api", encoding="utf-8")),
                            (destinations[1], lambda stage, _prepared: (
                                stage / "marker"
                            ).write_text("new-source", encoding="utf-8")),
                        ),
                            retain_transaction=True,
                            transaction_binding={
                                "result_generation_identity": generation,
                                "validation_run_identity": validation,
                                "validation_result_sha256": (
                                    validation_sha256
                                ),
                                "activation_identity": activation,
                            },
                        )
                        if state == "gate_passed":
                            binary_report.mark_report_publication_gate_passed(
                                destinations,
                                expected_transaction_id=transaction[
                                    "transaction_id"
                                ],
                                expected_binding=transaction["binding"],
                                gate_name="jar_compare",
                                strict_risk_gate=False,
                            )
                        normalized = [
                            Path(item).resolve() for item in destinations
                        ]
                        transaction_path, _group = (
                            binary_report._publication_transaction_path(
                                normalized
                            )
                        )
                        payload = run_step.read_json(transaction_path)
                        if transaction_kind == "legacy_v2":
                            payload["schema"] = (
                                binary_report
                                ._LEGACY_REPORT_PUBLICATION_TRANSACTION_SCHEMA
                            )
                            payload["binding"].pop(
                                "report_implementation_identity"
                            )
                            payload.pop("gate_receipt")
                        else:
                            payload["binding"][
                                "report_implementation_identity"
                            ] = "0" * 64
                            if state == "gate_passed":
                                previous_gate_receipt = payload["gate_receipt"]
                                payload["gate_receipt"] = (
                                    binary_report._new_report_gate_receipt(
                                        payload,
                                        gate_name=previous_gate_receipt[
                                            "gate_name"
                                        ],
                                        strict_risk_gate=(
                                            previous_gate_receipt[
                                                "strict_risk_gate"
                                            ]
                                        ),
                                    )
                                )
                        binary_report._atomic_json(transaction_path, payload)
                        patch_target = (
                            "rollback_report_publication"
                            if failed_layer == "report"
                            else "compare_and_restore_active_binary_generation"
                        )

                        with patch.object(
                            run_step,
                            patch_target,
                            side_effect=OSError("injected rollback failure"),
                        ), self.assertRaises(run_step.StepError) as caught:
                            run_step._recover_binary_step4_transaction(report)
                        rollback_status = caught.exception.diagnostic[
                            "rollback_status"
                        ]

                    self.assertIn(
                        "BINARY_STEP4_TRANSACTION_RECOVERY_FAILED",
                        caught.exception.reason_codes,
                    )
                    failed_status_key = (
                        "report_publication_rollback"
                        if failed_layer == "report"
                        else "active_generation_rollback"
                    )
                    self.assertTrue(
                        rollback_status[failed_status_key].startswith(
                            "rollback_failed:"
                        )
                    )

    def test_unknown_report_transaction_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            destinations = run_step._step4_report_publication_destinations(
                report
            )
            for destination, value in zip(
                destinations, ("old-api", "old-source")
            ):
                destination.mkdir(parents=True)
                (destination / "marker").write_text(value, encoding="utf-8")
            transaction = binary_report._stage_directory_group((
                (destinations[0], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new-api", encoding="utf-8")),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new-source", encoding="utf-8")),
            ), retain_transaction=True)
            normalized = [Path(item).resolve() for item in destinations]
            transaction_path, _group = (
                binary_report._publication_transaction_path(normalized)
            )
            payload = run_step.read_json(transaction_path)
            payload["schema"] = (
                "java-upgrade-analyzer.binary-report-publication-transaction.v999"
            )
            binary_report._atomic_json(transaction_path, payload)

            with self.assertRaises(binary_report.BinaryReportError) as caught:
                binary_report.report_publication_transaction_recovery_metadata(
                    destinations
                )
            published = tuple(
                (destination / "marker").read_text(encoding="utf-8")
                for destination in destinations
            )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_RECOVERY_INVALID",
        )
        self.assertEqual(published, ("old-api", "old-source"))

    def test_step4_gate_or_finalize_failure_rolls_back_all_three_state_layers(self):
        for failure_phase in ("gate", "finalize"):
            with self.subTest(failure_phase=failure_phase), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                report = root / ".upgrade-report"
                destinations = run_step._step4_report_publication_destinations(
                    report
                )
                for destination, value in zip(
                    destinations, ("old-api", "old-source")
                ):
                    destination.mkdir(parents=True)
                    (destination / "marker").write_text(value, encoding="utf-8")
                transaction = binary_report._stage_directory_group((
                    (destinations[0], lambda stage, _prepared: (
                        stage / "marker"
                    ).write_text("new-api", encoding="utf-8")),
                    (destinations[1], lambda stage, _prepared: (
                        stage / "marker"
                    ).write_text("new-source", encoding="utf-8")),
                ), retain_transaction=True)
                binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
                active_path = binary_root / "active_binary_generation.json"
                checkpoint = run_step._step4_validation_checkpoint_path(report)
                predecessor_identity = "a" * 64
                generation = "c" * 64
                activation = "d" * 64
                validation = "e" * 64
                predecessor = {
                    "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                    "result_generation_identity": predecessor_identity,
                    "generation_directory": (
                        f"binary_generations/{predecessor_identity}"
                    ),
                    "validation_run_identity": "1" * 64,
                    "validation_result_sha256": "2" * 64,
                }
                run_step.write_json(active_path, {
                    "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                    "result_generation_identity": generation,
                    "generation_directory": f"binary_generations/{generation}",
                    "validation_run_identity": validation,
                    "validation_result_sha256": "3" * 64,
                    "activation_identity": activation,
                    "activation_predecessor": predecessor,
                })
                run_step.write_json(checkpoint, {
                    "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
                    "status": "independent_validation_passed_pending_activation",
                    "result_generation_identity": generation,
                    "validation_run_identity": validation,
                    "activation_identity": activation,
                })
                result = {
                    "validation_checkpoint_retained": True,
                    "validation_checkpoint_path": str(checkpoint),
                    "result_generation_identity": generation,
                    "validation_run_identity": validation,
                    "activation_identity": activation,
                    "report_publication_transaction": transaction,
                }
                gate_error = (
                    run_step.StepError("injected gate failure")
                    if failure_phase == "gate" else None
                )
                finalize_error = (
                    run_step.StepError("injected finalize failure")
                    if failure_phase == "finalize" else None
                )
                with patch.object(
                    run_step,
                    "run_gate",
                    side_effect=gate_error,
                ), patch.object(
                    run_step,
                    "_finalize_binary_step4_transaction",
                    side_effect=finalize_error,
                ):
                    with self.assertRaises(run_step.StepError) as caught:
                        run_step._complete_binary_step4_after_gate(
                            report_dir=report,
                            project_dir=root,
                            gate_name="jar_compare",
                            strict_risk_gate=False,
                            result=result,
                        )
                final_active = run_step.read_json(active_path)
                report_values = tuple(
                    (destination / "marker").read_text(encoding="utf-8")
                    for destination in destinations
                )
                checkpoint_retained = checkpoint.is_file()
                publication_state = (
                    binary_report.report_publication_transaction_state(
                        destinations
                    )
                )

            self.assertEqual(
                final_active["result_generation_identity"], predecessor_identity
            )
            self.assertEqual(report_values, ("old-api", "old-source"))
            self.assertTrue(checkpoint_retained)
            self.assertEqual(publication_state, "absent")
            self.assertEqual(
                caught.exception.diagnostic["active_generation_rollback"],
                "restored_lock_observed_predecessor",
            )
            self.assertEqual(
                caught.exception.diagnostic["report_publication_rollback"],
                "restored_previous_reports",
            )

    def test_step4_startup_never_treats_matching_report_as_gate_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            active_path = binary_root / "active_binary_generation.json"
            summary = run_step.step4_api_changes_dir(report) / "summary.json"
            predecessor_identity = self._write_release_authorized_generation(
                binary_root, marker="2"
            )
            generation = self._write_release_authorized_generation(
                binary_root, marker="3"
            )
            activation = "d" * 64
            predecessor = {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": predecessor_identity,
                "generation_directory": f"binary_generations/{predecessor_identity}",
                "validation_run_identity": "1" * 64,
                "validation_result_sha256": "2" * 64,
            }
            run_step.write_json(active_path, {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": generation,
                "generation_directory": f"binary_generations/{generation}",
                "validation_run_identity": "3" * 64,
                "validation_result_sha256": "4" * 64,
                "activation_identity": activation,
                "activation_predecessor": predecessor,
            })
            run_step.write_json(checkpoint, {
                "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
                "status": "independent_validation_passed_pending_activation",
                "result_generation_identity": generation,
                "validation_run_identity": "3" * 64,
                "activation_identity": activation,
            })
            run_step.write_json(
                summary, {"result_generation_identity": generation}
            )

            with self.assertRaises(run_step.StepError) as caught:
                run_step._recover_binary_step4_transaction(report)
            final_active = run_step.read_json(active_path)
            checkpoint_retained = checkpoint.is_file()

        self.assertIn(
            "BINARY_STEP4_REPORT_RECOVERY_EVIDENCE_MISSING",
            caught.exception.reason_codes,
        )
        self.assertEqual(
            final_active["result_generation_identity"], predecessor_identity
        )
        self.assertTrue(checkpoint_retained)

    def test_step4_startup_allows_validated_checkpoint_before_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            active_path = binary_root / "active_binary_generation.json"
            predecessor_identity = self._write_release_authorized_generation(
                binary_root, marker="c"
            )
            generation = self._write_release_authorized_generation(
                binary_root, marker="d"
            )
            activation = "d" * 64
            run_step.write_json(active_path, {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": predecessor_identity,
                "generation_directory": f"binary_generations/{predecessor_identity}",
                "validation_run_identity": "1" * 64,
                "validation_result_sha256": "2" * 64,
            })
            run_step.write_json(checkpoint, {
                "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
                "status": "independent_validation_passed_pending_activation",
                "result_generation_identity": generation,
                "validation_run_identity": "3" * 64,
                "activation_identity": activation,
            })

            recovery = run_step._recover_binary_step4_transaction(report)
            final_active = run_step.read_json(active_path)
            checkpoint_retained = checkpoint.is_file()

        self.assertEqual(recovery, "validation_checkpoint_pending_activation")
        self.assertEqual(
            final_active["result_generation_identity"], predecessor_identity
        )
        self.assertTrue(checkpoint_retained)

    def test_step4_startup_preserves_prevalidation_resume_checkpoints(self):
        for status in (
            "awaiting_independent_validation",
            "independent_validation_failed",
        ):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                report = Path(tmp).resolve() / ".upgrade-report"
                checkpoint = run_step._step4_validation_checkpoint_path(
                    report
                )
                run_step.write_json(checkpoint, {
                    "schema": (
                        "java-upgrade-analyzer."
                        "binary-generation-validation-checkpoint.v3"
                    ),
                    "status": status,
                    "result_generation_identity": "a" * 64,
                })

                recovery = run_step._recover_binary_step4_transaction(report)

                self.assertEqual(
                    recovery, "validation_checkpoint_resume_required"
                )
                self.assertTrue(checkpoint.is_file())
                disposition = run_step._classify_step4_recovery_disposition(
                    report,
                    recovery,
                    expected_gate_name="jar_compare",
                    expected_strict_risk_gate=False,
                )
                self.assertEqual(
                    disposition["action"],
                    run_step._STEP4_RELEASE_RESUME_PIPELINE,
                )

    def test_explicit_rerun_discards_schema_less_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text("{}\n", encoding="utf-8")

            with self.assertRaises(run_step.StepError) as blocked:
                run_step._recover_binary_step4_transaction(report)
            recovery = run_step._recover_binary_step4_transaction(
                report, discard_invalid_checkpoint=True
            )

            self.assertIn(
                "BINARY_STEP4_TRANSACTION_RECOVERY_FAILED",
                blocked.exception.reason_codes,
            )
            self.assertEqual(
                recovery, "discarded_invalid_checkpoint_for_rerun"
            )
            self.assertFalse(checkpoint.exists())

    def test_startup_checkpoint_discard_requires_explicit_regeneration(self):
        auto_args = SimpleNamespace(step="auto")
        explicit_args = SimpleNamespace(step="step4")

        self.assertFalse(
            run_step._startup_discards_invalid_step4_checkpoint(
                auto_args, {}, "step4"
            )
        )
        self.assertTrue(
            run_step._startup_discards_invalid_step4_checkpoint(
                explicit_args, {}, "step4"
            )
        )
        self.assertTrue(
            run_step._startup_discards_invalid_step4_checkpoint(
                auto_args,
                {"action": "restart_from_step", "restart_step_id": "step3"},
                "step3",
            )
        )

    def test_step4_startup_rolls_back_activation_before_report_started(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            active_path = binary_root / "active_binary_generation.json"
            predecessor_identity = self._write_release_authorized_generation(
                binary_root, marker="e"
            )
            generation = self._write_release_authorized_generation(
                binary_root, marker="f"
            )
            activation = "d" * 64
            predecessor = {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": predecessor_identity,
                "generation_directory": f"binary_generations/{predecessor_identity}",
                "validation_run_identity": "1" * 64,
                "validation_result_sha256": "2" * 64,
            }
            run_step.write_json(active_path, {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": generation,
                "generation_directory": f"binary_generations/{generation}",
                "validation_run_identity": "3" * 64,
                "validation_result_sha256": "4" * 64,
                "activation_identity": activation,
                "activation_predecessor": predecessor,
            })
            run_step.write_json(checkpoint, {
                "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
                "status": "independent_validation_passed_pending_activation",
                "result_generation_identity": generation,
                "validation_run_identity": "3" * 64,
                "activation_identity": activation,
            })

            recovery = run_step._recover_binary_step4_transaction(report)
            final_active = run_step.read_json(active_path)

        self.assertEqual(
            recovery, "rolled_back_activation_before_report_publication"
        )
        self.assertEqual(
            final_active["result_generation_identity"], predecessor_identity
        )

    def test_step4_startup_recovers_process_death_with_pending_gate_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            destinations = run_step._step4_report_publication_destinations(report)
            for destination, value in zip(
                destinations, ("old-api", "old-source")
            ):
                destination.mkdir(parents=True)
                (destination / "marker").write_text(value, encoding="utf-8")
            transaction = binary_report._stage_directory_group((
                (destinations[0], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new-api", encoding="utf-8")),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new-source", encoding="utf-8")),
            ), retain_transaction=True)
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            active_path = binary_root / "active_binary_generation.json"
            predecessor_identity = self._write_release_authorized_generation(
                binary_root, marker="f"
            )
            generation = self._write_release_authorized_generation(
                binary_root, marker="1"
            )
            activation = "d" * 64
            predecessor = {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": predecessor_identity,
                "generation_directory": f"binary_generations/{predecessor_identity}",
                "validation_run_identity": "1" * 64,
                "validation_result_sha256": "2" * 64,
            }
            run_step.write_json(active_path, {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": generation,
                "generation_directory": f"binary_generations/{generation}",
                "validation_run_identity": "3" * 64,
                "validation_result_sha256": "4" * 64,
                "activation_identity": activation,
                "activation_predecessor": predecessor,
            })
            run_step.write_json(checkpoint, {
                "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
                "status": "independent_validation_passed_pending_activation",
                "result_generation_identity": generation,
                "validation_run_identity": "3" * 64,
                "activation_identity": activation,
            })

            recovery = run_step._recover_binary_step4_transaction(report)
            final_active = run_step.read_json(active_path)
            report_values = tuple(
                (destination / "marker").read_text(encoding="utf-8")
                for destination in destinations
            )
            state = binary_report.report_publication_transaction_state(
                destinations
            )
            checkpoint_retained = checkpoint.is_file()

        self.assertEqual(recovery, "rolled_back_interrupted_transaction")
        self.assertEqual(
            final_active["result_generation_identity"], predecessor_identity
        )
        self.assertEqual(report_values, ("old-api", "old-source"))
        self.assertEqual(state, "absent")
        self.assertTrue(checkpoint_retained)

    def test_step4_private_publish_does_not_require_performance_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            generation = "a" * 64
            activation = "c" * 64
            result = {
                "result_generation_identity": generation,
                "activation_identity": activation,
            }

            def publish_without_guard(*_args, **kwargs):
                self.assertIsNone(kwargs.get("publication_guard"))
                return True

            with patch.object(
                run_step,
                "read_pending_binary_generation",
                return_value={"activation_identity": activation},
            ), patch.object(
                run_step,
                "publish_pending_binary_generation",
                side_effect=publish_without_guard,
            ):
                outcome = run_step._seal_binary_step4_activation(
                    report, result
                )

        self.assertEqual(outcome, "published_private_candidate")

    def test_step4_gate_success_commits_reports_active_and_checkpoint_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            report = root / ".upgrade-report"
            destinations = run_step._step4_report_publication_destinations(report)
            for destination, value in zip(
                destinations, ("old-api", "old-source")
            ):
                destination.mkdir(parents=True)
                (destination / "marker").write_text(value, encoding="utf-8")
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            active_path = binary_root / "active_binary_generation.json"
            generation = self._write_release_authorized_generation(
                binary_root, marker="5"
            )
            activation = "d" * 64
            validation = "e" * 64
            binary_output._write_active_descriptor(binary_root, {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": generation,
                "generation_directory": f"binary_generations/{generation}",
                "validation_run_identity": validation,
                "validation_result_sha256": "4" * 64,
                "activation_identity": activation,
                "activation_predecessor": None,
            }, expect_missing=True)
            run_step.write_json(checkpoint, {
                "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
                "status": "independent_validation_passed_pending_activation",
                "result_generation_identity": generation,
                "validation_run_identity": validation,
                "activation_identity": activation,
            })

            def write_api(stage, _prepared):
                (stage / "marker").write_text("new-api", encoding="utf-8")
                run_step.write_json(
                    stage / "summary.json",
                    {"result_generation_identity": generation},
                )

            transaction = binary_report._stage_directory_group((
                (destinations[0], write_api),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("new-source", encoding="utf-8")),
            ),
                retain_transaction=True,
                transaction_binding={
                    "result_generation_identity": generation,
                    "validation_run_identity": validation,
                    "validation_result_sha256": "4" * 64,
                    "activation_identity": activation,
                },
            )
            result = {
                "validation_checkpoint_retained": True,
                "validation_checkpoint_path": str(checkpoint),
                "result_generation_identity": generation,
                "validation_run_identity": validation,
                "activation_identity": activation,
                "report_publication_transaction": transaction,
            }

            with patch.object(
                run_step, "run_gate", return_value=None
            ), patch.object(
                run_step,
                "reconcile_current_release",
                return_value={
                    "step4": {"status": "current"},
                    "step5": {"status": "stale"},
                    "step6": {"status": "stale"},
                },
            ), patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                return_value=None,
            ):
                committed = run_step._complete_binary_step4_after_gate(
                    report_dir=report,
                    project_dir=root,
                    gate_name="jar_compare",
                    strict_risk_gate=False,
                    result=result,
                )
            final_active = run_step.read_json(active_path)
            report_values = tuple(
                (destination / "marker").read_text(encoding="utf-8")
                for destination in destinations
            )
            checkpoint_exists = checkpoint.exists()
            state = binary_report.report_publication_transaction_state(
                destinations
            )

        self.assertTrue(committed)
        self.assertEqual(final_active["result_generation_identity"], generation)
        self.assertEqual(report_values, ("new-api", "new-source"))
        self.assertFalse(checkpoint_exists)
        self.assertEqual(state, "absent")

    def test_step4_retains_checkpoint_until_activation_receipt_commit(self):
        events = []
        result = {
            "activation_identity": "a" * 64,
            "report_publication_transaction": {
                "transaction_id": "transaction-1",
                "binding": {},
            },
        }

        def finalize(_report, _result, *, delete_checkpoint=True):
            events.append(
                "delete_checkpoint"
                if delete_checkpoint
                else "validate_checkpoint"
            )
            return True

        with patch.object(
            run_step,
            "_step4_report_publication_expectation",
            return_value={"transaction_id": "transaction-1", "binding": {}},
        ), patch.object(
            run_step, "run_gate", return_value=None
        ), patch.object(
            run_step,
            "mark_report_publication_gate_passed",
            return_value={"gate_receipt_identity": "receipt-1"},
        ), patch.object(
            run_step, "publish_report_publication", return_value=True
        ), patch.object(
            run_step, "_seal_binary_step4_activation", return_value=True
        ), patch.object(
            run_step,
            "_finalize_binary_step4_transaction",
            side_effect=finalize,
        ), patch.object(
            run_step,
            "_commit_binary_step4_activation_receipt",
            side_effect=lambda *_args: events.append("commit_activation"),
        ), patch.object(
            run_step,
            "commit_report_publication",
            side_effect=lambda *_args, **_kwargs: (
                events.append("commit_reports") or True
            ),
        ), patch.object(
            run_step,
            "reconcile_current_release",
            return_value={
                "step4": {"status": "current"},
                "step5": {"status": "stale"},
                "step6": {"status": "stale"},
            },
        ):
            run_step._complete_binary_step4_after_gate(
                report_dir=Path("/unused/report"),
                project_dir=Path("/unused/project"),
                gate_name="jar_compare",
                strict_risk_gate=False,
                result=result,
            )

        self.assertEqual(events, [
            "validate_checkpoint",
            "commit_activation",
            "delete_checkpoint",
            "commit_reports",
        ])

    def test_step4_gate_passed_recovery_rejects_consistent_report_and_active_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            destinations = run_step._step4_report_publication_destinations(report)
            generation = "a" * 64
            replacement_generation = "b" * 64
            validation = "c" * 64
            validation_sha256 = "d" * 64
            activation = "e" * 64
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            active_path = binary_root / "active_binary_generation.json"
            run_step.write_json(active_path, {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": generation,
                "generation_directory": f"binary_generations/{generation}",
                "validation_run_identity": validation,
                "validation_result_sha256": validation_sha256,
                "activation_identity": activation,
                "activation_predecessor": None,
            })

            def write_api(stage, _prepared):
                run_step.write_json(stage / "summary.json", {
                    "result_generation_identity": generation,
                })

            transaction = binary_report._stage_directory_group((
                (destinations[0], write_api),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("source", encoding="utf-8")),
            ),
                retain_transaction=True,
                transaction_binding={
                    "result_generation_identity": generation,
                    "validation_run_identity": validation,
                    "validation_result_sha256": validation_sha256,
                    "activation_identity": activation,
                },
            )
            binary_report.mark_report_publication_gate_passed(
                destinations,
                expected_transaction_id=transaction["transaction_id"],
                expected_binding=transaction["binding"],
                gate_name="jar_compare",
                strict_risk_gate=False,
            )

            # Replace both private candidate identities consistently.  The
            # durable report digest and activation CAS must prevent recovery
            # from either committing or claiming a successful rollback.
            candidate_api = Path(
                transaction["candidate_destinations"][0]
            )
            run_step.write_json(candidate_api / "summary.json", {
                "result_generation_identity": replacement_generation,
            })
            pending_path = (
                binary_root
                / "binary_observability"
                / "pending_active_binary_generation.json"
            )
            run_step.write_json(pending_path, {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": replacement_generation,
                "generation_directory": (
                    f"binary_generations/{replacement_generation}"
                ),
                "validation_run_identity": validation,
                "validation_result_sha256": validation_sha256,
                "activation_identity": activation,
                "activation_predecessor": None,
                "activation_state": "pending",
            })

            with self.assertRaises(
                binary_report.BinaryReportError
            ) as caught:
                run_step._recover_binary_step4_transaction(
                    report,
                    expected_gate_name="jar_compare",
                    expected_strict_risk_gate=False,
                )
            state = binary_report.report_publication_transaction_state(
                destinations
            )

        self.assertEqual(
            caught.exception.reason_code,
            "BINARY_REPORT_PUBLICATION_CONTENT_MISMATCH",
        )
        self.assertEqual(state, "gate_passed")

    def test_step4_recovers_crash_after_active_seal_before_report_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            destinations = run_step._step4_report_publication_destinations(report)
            validation = "b" * 64
            validation_sha256 = "c" * 64
            activation = "d" * 64
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            active_path = binary_root / "active_binary_generation.json"
            generation = self._write_release_authorized_generation(
                binary_root, marker="6"
            )
            binary_output._write_active_descriptor(binary_root, {
                "schema": "java-upgrade-analyzer.active-binary-generation.v1",
                "result_generation_identity": generation,
                "generation_directory": f"binary_generations/{generation}",
                "validation_run_identity": validation,
                "validation_result_sha256": validation_sha256,
                "activation_identity": activation,
                "activation_predecessor": None,
            }, expect_missing=True)

            transaction = binary_report._stage_directory_group((
                (destinations[0], lambda stage, _prepared: run_step.write_json(
                    stage / "summary.json",
                    {"result_generation_identity": generation},
                )),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("source", encoding="utf-8")),
            ),
                retain_transaction=True,
                transaction_binding={
                    "result_generation_identity": generation,
                    "validation_run_identity": validation,
                    "validation_result_sha256": validation_sha256,
                    "activation_identity": activation,
                },
            )
            binary_report.mark_report_publication_gate_passed(
                destinations,
                expected_transaction_id=transaction["transaction_id"],
                expected_binding=transaction["binding"],
                gate_name="jar_compare",
                strict_risk_gate=False,
            )
            # This recovery fixture intentionally models only the descriptor
            # transaction; generation byte-integrity has dedicated
            # binary_output coverage.
            with patch.object(
                binary_output,
                "_verify_pending_generation_integrity",
                return_value=None,
            ):
                self.assertTrue(run_step.seal_active_binary_generation(
                    binary_root,
                    expected_current_identity=generation,
                    expected_activation_identity=activation,
                ))

            recovery = run_step._recover_binary_step4_transaction(
                report,
                expected_gate_name="jar_compare",
                expected_strict_risk_gate=False,
            )
            active = run_step.read_json(active_path)
            state = binary_report.report_publication_transaction_state(
                destinations
            )

        self.assertEqual(recovery, "completed_gate_passed_transaction")
        self.assertNotIn("activation_identity", active)
        self.assertNotIn("activation_predecessor", active)
        self.assertEqual(state, "absent")

    def test_step4_finalize_and_recovery_reject_active_descriptor_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp).resolve() / ".upgrade-report"
            binary_root = report / run_step.BINARY_OUTPUT_RELATIVE_PATH
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            generation = "a" * 64
            validation = "b" * 64
            activation = "c" * 64
            run_step.write_json(checkpoint, {
                "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
                "status": "independent_validation_passed_pending_activation",
                "result_generation_identity": generation,
                "validation_run_identity": validation,
                "activation_identity": activation,
            })
            external = Path(tmp).resolve() / "external-active.json"
            run_step.write_json(external, {
                "result_generation_identity": generation,
                "validation_run_identity": validation,
                "validation_result_sha256": "d" * 64,
                "activation_identity": activation,
            })
            external_bytes = external.read_bytes()
            active_path = binary_root / "active_binary_generation.json"
            try:
                active_path.symlink_to(external)
            except OSError as error:
                self.skipTest(f"symlinks unavailable: {error}")
            destinations = run_step._step4_report_publication_destinations(
                report
            )
            transaction = binary_report._stage_directory_group((
                (destinations[0], lambda stage, _prepared: run_step.write_json(
                    stage / "summary.json",
                    {"result_generation_identity": generation},
                )),
                (destinations[1], lambda stage, _prepared: (
                    stage / "marker"
                ).write_text("source", encoding="utf-8")),
            ),
                retain_transaction=True,
                transaction_binding={
                    "result_generation_identity": generation,
                    "validation_run_identity": validation,
                    "validation_result_sha256": "d" * 64,
                    "activation_identity": activation,
                },
            )
            gate_receipt = binary_report.mark_report_publication_gate_passed(
                destinations,
                expected_transaction_id=transaction["transaction_id"],
                expected_binding=transaction["binding"],
                gate_name="jar_compare",
                strict_risk_gate=False,
            )
            result = {
                "validation_checkpoint_retained": True,
                "validation_checkpoint_path": str(checkpoint),
                "result_generation_identity": generation,
                "validation_run_identity": validation,
                "activation_identity": activation,
                "report_publication_transaction": transaction,
                "report_publication_gate_receipt": gate_receipt,
            }

            with self.assertRaises(run_step.StepError) as finalize_error:
                run_step._finalize_binary_step4_transaction(report, result)
            with self.assertRaises(run_step.StepError) as recovery_error:
                run_step._recover_binary_step4_transaction(
                    report,
                    expected_gate_name="jar_compare",
                    expected_strict_risk_gate=False,
                )

            self.assertTrue(checkpoint.is_file())
            self.assertEqual(external.read_bytes(), external_bytes)

        self.assertIn(
            "BINARY_STEP4_ACTIVE_DESCRIPTOR_INVALID",
            finalize_error.exception.reason_codes,
        )
        self.assertIn(
            "BINARY_STEP4_ACTIVE_DESCRIPTOR_INVALID",
            recovery_error.exception.reason_codes,
        )

    def test_step4_recovery_rejects_checkpoint_links_and_fifo(self):
        checkpoint_payload = {
            "schema": "java-upgrade-analyzer.binary-generation-validation-checkpoint.v3",
            "status": "independent_validation_passed_pending_activation",
            "result_generation_identity": "a" * 64,
            "validation_run_identity": "b" * 64,
            "activation_identity": "c" * 64,
        }
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                report = Path(tmp).resolve() / ".upgrade-report"
                checkpoint = run_step._step4_validation_checkpoint_path(report)
                checkpoint.parent.mkdir(parents=True)
                external = Path(tmp).resolve() / "external-checkpoint.json"
                external_bytes = json.dumps(checkpoint_payload).encode("utf-8")
                if kind == "fifo":
                    if not hasattr(os, "mkfifo"):
                        self.skipTest("FIFO is unavailable")
                    try:
                        os.mkfifo(checkpoint)
                    except OSError as error:
                        self.skipTest(f"FIFO is unavailable: {error}")
                else:
                    external.write_bytes(external_bytes)
                    try:
                        if kind == "symlink":
                            checkpoint.symlink_to(external)
                        else:
                            os.link(external, checkpoint)
                    except OSError as error:
                        self.skipTest(f"{kind} is unavailable: {error}")

                with self.assertRaises(run_step.StepError) as caught:
                    run_step._recover_binary_step4_transaction(report)

                self.assertIn(
                    "BINARY_STEP4_TRANSACTION_CHECKPOINT_INVALID",
                    caught.exception.reason_codes,
                )
                if kind != "fifo":
                    self.assertEqual(external.read_bytes(), external_bytes)

    def test_binary_pipeline_config_intent_targets_step4_and_is_persisted(self):
        response = {"action": "continue", "binary_pipeline_config": "binary.json"}

        self.assertEqual(
            run_step.infer_non_pending_target_step_from_payload(response),
            "step4",
        )
        updated = run_step.merge_user_response_into_run_context(
            {},
            response,
            Path.cwd(),
        )
        self.assertEqual(updated["binary_pipeline_config"], str(Path.cwd() / "binary.json"))

    def test_json_reader_rejects_bom_prefixed_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            invalid_path = Path(tmp) / "invalid.json"
            invalid_path.write_bytes(
                b"\xef\xbb\xbf" + '{"message":"中文"}'.encode("utf-8")
            )
            with self.assertRaises(json.JSONDecodeError):
                run_step.read_json(invalid_path)


    def test_step0_artifact_card_does_not_show_unpinned_local_candidates(self):
        interaction = run_step.build_step0_confirmation_interaction(
            {
                "base_artifact_path": "/artifacts/base.jar",
                "current_artifact_path": "/artifacts/current.jar",
                "project_scope": {
                    "candidate_modules": ["app", "services/order-service"],
                },
            }
        )

        card = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertIn("target_module", interaction["required_fields"])
        self.assertNotIn("检测到的目标模块候选", card)
        self.assertNotIn("`app`", card)
        self.assertNotIn("`services/order-service`", card)

    def test_auto_mode_runs_until_next_material_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"].update({"current_step": "step3", "completed_step": "step2"})
            state["step3"]["input"] = {
                "target_module": ".",
                "source_dirs": [str(source_dir)],
                "source_dirs_status": "explicit",
            }
            run_step.save_main_state(report_dir, state)
            executed = []

            def fake_execute(step_id, _args, _steps, _context, **_kwargs):
                executed.append(step_id)
                if step_id == "step4":
                    return {
                        "kind": "review",
                        "status": "awaiting_user_input",
                        "step_id": "step4",
                        "question": "请选择全量或部分分析范围。",
                        "options": [{"id": "continue"}, {"id": "cancel"}],
                    }
                return None

            manifest = {
                "auto_run_until_checkpoint": True,
            }
            steps = {
                "step3": {"gate": "scan", "interaction": None},
                "step4": {
                    "gate": "binary_generation",
                    "requires_scope_confirmation": True,
                },
            }
            with patch.object(
                run_step, "contract_payload", return_value={"status": "passed", "checks": []}
            ), patch.object(
                run_step, "load_manifest", return_value=(manifest, steps)
            ), patch.object(
                run_step, "detect_integrity_repair_step", return_value=None
            ), patch.object(
                run_step, "detect_build_tool", return_value="maven"
            ), patch.object(
                run_step, "execute_step", side_effect=fake_execute
            ), patch.object(
                run_step,
                "_recover_and_apply_step4_startup_state",
                return_value={
                    "action": run_step._STEP4_RELEASE_CURRENT,
                    "applied": False,
                    "forced_step_id": "",
                    "discard_structured_response": False,
                },
            ), patch.object(
                run_step,
                "_apply_downstream_release_startup_state",
                return_value={
                    "forced_step_id": "",
                    "discard_structured_response": False,
                    "release": {},
                },
            ):
                exit_code = run_step.main(
                    [
                        "--step", "auto",
                        "--project-dir", str(project_dir),
                        "--report-dir", str(report_dir),
                    ]
                )

            saved = run_step.load_main_state(report_dir)

        self.assertEqual(exit_code, run_step.EXIT_AWAITING_USER)
        self.assertEqual(executed, ["step3", "step4"])
        self.assertEqual(saved["state"]["completed_step"], "step4")
        self.assertEqual(saved["state"]["pending_interaction"]["step_id"], "step4")

    def test_auto_mode_runs_system_reachability_and_report_without_extra_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"].update({"current_step": "step5", "completed_step": "step4"})
            state["step5"]["input"] = {
                "target_module": ".",
                "source_dirs": [str(source_dir)],
                "source_dirs_status": "explicit",
            }
            run_step.save_main_state(report_dir, state)
            executed = []

            def fake_execute(step_id, _args, _steps, _context, **_kwargs):
                executed.append(step_id)
                return None

            manifest = {"auto_run_until_checkpoint": True}
            steps = {
                "step5": {
                    "gate": "binary_report",
                    "auto_continue_on_success": True,
                    "interaction": None,
                },
                "step6": {"gate": "report", "interaction": None},
            }
            with patch.object(
                run_step, "contract_payload", return_value={"status": "passed", "checks": []}
            ), patch.object(
                run_step, "load_manifest", return_value=(manifest, steps)
            ), patch.object(
                run_step, "detect_integrity_repair_step", return_value=None
            ), patch.object(
                run_step, "detect_build_tool", return_value="maven"
            ), patch.object(
                run_step, "execute_step", side_effect=fake_execute
            ), patch.object(
                run_step,
                "_recover_and_apply_step4_startup_state",
                return_value={
                    "action": run_step._STEP4_RELEASE_CURRENT,
                    "applied": False,
                    "forced_step_id": "",
                    "discard_structured_response": False,
                },
            ), patch.object(
                run_step,
                "_apply_downstream_release_startup_state",
                return_value={
                    "forced_step_id": "",
                    "discard_structured_response": False,
                    "release": {},
                },
            ):
                exit_code = run_step.main(
                    [
                        "--step", "auto",
                        "--project-dir", str(project_dir),
                        "--report-dir", str(report_dir),
                    ]
                )

            saved = run_step.load_main_state(report_dir)

        self.assertEqual(exit_code, 0)
        self.assertEqual(executed, ["step5", "step6"])
        self.assertEqual(saved["state"]["current_step"], "done")
        self.assertEqual(saved["state"]["completed_step"], "step6")
        self.assertIn(
            saved["state"]["status"],
            {"completed", "completed_with_limits"},
        )

    def test_step4_scope_review_is_preserved_and_step5_success_review_auto_continues(self):
        interaction = {
            "status": "awaiting_user_input",
            "options": [{"id": "continue"}, {"id": "cancel"}],
        }
        manifest = {
            "step4": {
                "auto_continue_on_success": True,
                "requires_scope_confirmation": True,
            },
            "step5": {"auto_continue_on_success": True},
        }

        self.assertFalse(
            run_step.should_auto_continue_success_review("step4", interaction, manifest)
        )
        self.assertTrue(
            run_step.should_auto_continue_success_review("step5", interaction, manifest)
        )
        self.assertFalse(
            run_step.should_auto_continue_success_review(
                "step4",
                {**interaction, "reason_code": "step4_git_refs_need_confirmation"},
                manifest,
            )
        )
        self.assertFalse(
            run_step.should_auto_continue_success_review("step2", interaction, manifest)
        )

    def test_main_auto_continues_routine_step5_success_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step5"
            state["state"]["completed_step"] = "step4"
            run_step.save_main_state(report_dir, state)
            routine_review = {
                "status": "awaiting_user_input",
                "step_id": "step5",
                "options": [{"id": "continue"}, {"id": "cancel"}],
            }

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step", "step5",
                    "--project-dir", str(project_dir),
                    "--report-dir", str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=(
                    {},
                    {
                        "step5": {
                            "gate": "binary_report",
                            "auto_continue_on_success": True,
                        }
                    },
                ),
            ), patch.object(
                run_step,
                "execute_step",
                return_value=routine_review,
            ), patch.object(
                run_step,
                "_recover_and_apply_step4_startup_state",
                return_value={
                    "action": run_step._STEP4_RELEASE_CURRENT,
                    "applied": False,
                    "forced_step_id": "",
                    "discard_structured_response": False,
                },
            ), patch.object(
                run_step,
                "_apply_downstream_release_startup_state",
                return_value={
                    "forced_step_id": "",
                    "discard_structured_response": False,
                    "release": {},
                },
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)
            informational = run_step.read_json(
                report_dir / ".runtime" / "state" / "interaction.json"
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(saved["state"]["current_step"], "step6")
        self.assertEqual(saved["state"]["completed_step"], "step5")
        self.assertEqual(saved["state"]["status"], "ready")
        self.assertIsNone(saved["state"]["pending_interaction"])
        self.assertEqual(informational["status"], "informational")
        self.assertEqual(informational["event"], "step_completed_information")
        self.assertFalse(informational["must_wait_for_user_reply"])
        self.assertEqual(informational["exit_code"], 0)
        card = "\n".join(informational["user_decision_card"])
        self.assertIn("阶段结果：", card)
        self.assertIn("本卡无需回复", card)
        self.assertNotIn("为什么暂停", card)

    def test_step5_generates_standard_four_state_card_when_manifest_skips_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            call_chain_dir = report_dir / "evidence" / "call_chain"
            call_chain_dir.mkdir(parents=True)
            (call_chain_dir / "summary.json").write_text(
                json.dumps({
                    "reachable": 2,
                    "uncertain": 4,
                    "not_analyzed": 5,
                    "not_found_in_static_analysis": 6,
                }),
                encoding="utf-8",
            )
            payload = run_step.build_interaction_payload(
                "step5",
                report_dir,
                {
                    "step5": {
                        "title": "系统触达证据",
                        "interaction": None,
                        "auto_continue_on_success": True,
                    }
                },
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        self.assertIsNotNone(payload)
        informational = run_step.build_informational_success_interaction(
            "step5", payload
        )
        self.assertEqual(informational["status"], "informational")
        card = "\n".join(informational["user_decision_card"])
        self.assertIn("静态触达四态摘要（四类互斥）", card)
        self.assertIn("reachable（已确认静态触达）=2", card)
        self.assertNotIn("not_impacted", card)
        self.assertIn("uncertain（存在候选证据或已知分析边界）=4", card)
        self.assertIn("not_analyzed（输入不足或分析未完成）=5", card)
        self.assertIn("not_found_in_static_analysis（当前静态范围未找到路径）=6", card)
        self.assertIn("不表示安全", card)
        self.assertFalse(informational["decision_required"])

    def test_completion_cleanup_preserves_step5_informational_card_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            informational = run_step.build_informational_success_interaction(
                "step5",
                {
                    "step_id": "step5",
                    "checklist_lines": ["reachable=1", "uncertain=2"],
                },
            )
            run_step.save_interaction_file(report_dir, informational)

            run_step.clear_interaction_file(
                report_dir,
                preserve_informational=True,
            )
            preserved = run_step.read_json(
                report_dir / ".runtime" / "state" / "interaction.json"
            )

        self.assertEqual(preserved["status"], "informational")
        self.assertEqual(preserved["step_id"], "step5")
        self.assertEqual(preserved["event"], "step_completed_information")

    def test_legacy_nonterminal_completed_state_normalizes_to_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"].update(
                {
                    "current_step": "step6",
                    "completed_step": "step5",
                    "status": "completed",
                    "completion_summary": {"status": "completed"},
                }
            )

            normalized = run_step.ensure_main_state_structure(state, report_dir)

        self.assertEqual(normalized["state"]["current_step"], "step6")
        self.assertEqual(normalized["state"]["completed_step"], "step5")
        self.assertEqual(normalized["state"]["status"], "ready")
        self.assertIsNone(normalized["state"]["completion_summary"])

    def test_terminal_completed_state_remains_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            completion_summary = {"status": "completed", "finding_count": 0}
            state["state"].update(
                {
                    "current_step": "done",
                    "completed_step": "step6",
                    "status": "completed",
                    "completion_summary": completion_summary,
                }
            )

            normalized = run_step.ensure_main_state_structure(state, report_dir)

        self.assertEqual(normalized["state"]["status"], "completed")
        self.assertEqual(
            normalized["state"]["completion_summary"], completion_summary
        )

    def test_main_keeps_step4_scope_confirmation_even_if_auto_continue_is_misconfigured(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step4"
            state["state"]["completed_step"] = "step3"
            run_step.save_main_state(report_dir, state)
            scope_review = {
                "status": "awaiting_user_input",
                "step_id": "step4",
                "question": "请选择 Step5 的分析范围",
                "options": [{"id": "continue"}, {"id": "cancel"}],
            }

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step", "step4",
                    "--project-dir", str(project_dir),
                    "--report-dir", str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=(
                    {},
                    {
                        "step4": {
                            "gate": "binary_generation",
                            "auto_continue_on_success": True,
                            "requires_scope_confirmation": True,
                        }
                    },
                ),
            ), patch.object(
                run_step,
                "execute_step",
                return_value=scope_review,
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)

        self.assertEqual(exit_code, run_step.EXIT_AWAITING_USER)
        self.assertEqual(saved["state"]["current_step"], "step5")
        self.assertEqual(saved["state"]["status"], "awaiting_user_input")
        self.assertEqual(saved["state"]["pending_interaction"]["step_id"], "step4")

    def test_user_response_merges_active_maven_profiles_into_step0_context(self):
        updated = run_step.merge_user_response_into_run_context(
            {
                "active_maven_profiles": [],
                "source_dirs": ["/project/profile-a/src/main/java"],
                "source_dirs_status": "project_scope",
            },
            {"active_maven_profiles": ["boot", "boot"]},
            Path("/project"),
        )

        self.assertEqual(updated["active_maven_profiles"], ["boot"])
        self.assertNotIn("source_dirs", updated)
        self.assertNotIn("source_dirs_status", updated)
        self.assertEqual(
            run_step.infer_non_pending_target_step_from_payload(
                {"active_maven_profiles": ["boot"]}
            ),
            "step0",
        )

    def test_run_context_applies_explicit_maven_profiles_to_project_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report"
            (root / "pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>root</artifactId><version>1</version>
                <packaging>pom</packaging><profiles><profile><id>boot</id>
                <modules><module>application</module></modules></profile></profiles>
                </project>""",
                encoding="utf-8",
            )
            (root / "application/src/main/java").mkdir(parents=True)
            (root / "application/pom.xml").write_text(
                """<project><modelVersion>4.0.0</modelVersion>
                <groupId>com.acme</groupId><artifactId>application</artifactId>
                <version>1</version></project>""",
                encoding="utf-8",
            )
            args = self._make_default_args(root, report)
            args.target_module = ""
            args.active_maven_profiles = None

            context = run_step.build_run_context(
                args,
                existing={},
                seed_payload={
                    "target_module": "application",
                    "active_maven_profiles": ["boot"],
                },
            )

        self.assertEqual(context["active_maven_profiles"], ["boot"])
        self.assertEqual(
            context["project_scope"]["included_modules"], ["application"]
        )

    def _dep_dir(self, report_dir):
        return run_step.evidence_dependencies_dir(report_dir)

    def _context_dir(self, report_dir):
        return run_step.evidence_context_dir(report_dir)

    def _static_scan_dir(self, report_dir):
        return run_step.evidence_static_scan_dir(report_dir)

    def _api_changes_dir(self, report_dir):
        return run_step.evidence_api_changes_dir(report_dir)

    def _call_chain_dir(self, report_dir):
        return run_step.evidence_call_chain_dir(report_dir)

    def _runtime_state_dir(self, report_dir):
        return run_step.runtime_state_dir(report_dir)

    def _runtime_cache_dir(self, report_dir):
        return run_step.runtime_cache_dir(report_dir)

    def _deliverables_dir(self, report_dir):
        return run_step.deliverables_dir(report_dir)

    def _write_text(self, path, text, **kwargs):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path.write_text(text, **kwargs)

    def _make_default_args(self, project_dir, report_dir):
        return SimpleNamespace(
            project_dir=str(project_dir),
            report_dir=str(report_dir),
            base_branch=None,
            current_branch=None,
            modules=None,
            source_dirs=None,
            dependency_source_dirs=[],
            dependency_source_mappings=[],
            source_repo_hints=[],
            dependency_repo_mappings=[],
            dependency_git_ref_overrides_json="",
            base_artifact_path="",
            current_artifact_path="",
            base_source_project_dir="",
            current_source_project_dir="",
            base_jdk_home="",
            current_jdk_home="",
            primary_module="",
            manual_coord_overrides=[],
            include_test_scope=False,
            max_depth=None,
            tool="maven",
            strict_risk_gate=False,
            allow_unresolved=False,
        )


    def test_persist_step_error_saves_machine_readable_reason_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            error = run_step.StepError(
                "gate.py execution failed",
                reason_codes=["FINAL_ARTIFACT_JAR_EVIDENCE_MISSING"],
            )

            run_step.persist_step_error(state, "step4", report_dir, error)

            saved = run_step.read_json(run_step.main_state_path(report_dir))
            self.assertEqual(saved["state"]["status"], "blocked_by_system")
            self.assertEqual(
                saved["state"]["blocking_reason_codes"],
                ["FINAL_ARTIFACT_JAR_EVIDENCE_MISSING"],
            )


    def test_auto_step_reads_from_main_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step4"
            run_step.save_main_state(report_dir, state)

            loaded = run_step.load_main_state(report_dir)
            self.assertEqual(run_step.resolve_requested_step("auto", loaded), "step4")

    def test_user_response_accumulates_manual_coord_overrides_across_rounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            state = run_step.new_main_state(project_dir / ".upgrade-report")
            first_round = [
                f"lib-{index}:1.0 -> com.example:lib-{index}"
                for index in range(1, 10)
            ]
            state["step1"]["input"] = {
                "manual_coord_overrides": first_round,
            }

            _, updated = run_step.apply_user_response_to_main_state(
                state,
                {"step_id": "step1", "kind": "input_request"},
                {
                    "action": "rerun_current_step",
                    "manual_coord_overrides": [
                        "asm-util:7.1 -> org.ow2.asm:asm-util",
                    ],
                },
                project_dir,
                target_step_id="step1",
            )

            self.assertEqual(
                updated["manual_coord_overrides"],
                first_round + ["asm-util:7.1 -> org.ow2.asm:asm-util"],
            )

    def test_user_response_replaces_manual_identity_for_same_physical_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            state = run_step.new_main_state(project_dir / ".upgrade-report")
            state["step1"]["input"] = {
                "manual_artifact_identities": [{
                    "side": "current",
                    "lib_entry": "BOOT-INF/lib/renamed.jar",
                    "group_id": "org.example",
                    "artifact_id": "demo",
                    "version": "1.0",
                    "classifier": "",
                }],
            }

            _, updated = run_step.apply_user_response_to_main_state(
                state,
                {"step_id": "step1", "kind": "input_request"},
                {
                    "action": "rerun_current_step",
                    "manual_artifact_identities": [{
                        "side": "current",
                        "lib_entry": "BOOT-INF/lib/renamed.jar",
                        "group_id": "org.example",
                        "artifact_id": "demo",
                        "version": "2.0",
                        "classifier": "",
                    }],
                },
                project_dir,
                target_step_id="step1",
            )

            self.assertEqual(len(updated["manual_artifact_identities"]), 1)
            self.assertEqual(
                updated["manual_artifact_identities"][0]["version"],
                "2.0",
            )

    def test_materialize_step5_input_does_not_promote_step3_candidates_to_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            all_changed_path = report_dir / "all_changed_apis.csv"
            risk_candidates_path = report_dir / run_step.STEP3_RISK_CANDIDATES_FILE
            all_changed_path.write_text(
                "\n".join(
                    [
                        "coord,api_name,api_simple,api_signature,symbol_kind,change_type,confirmed,severity,source,analysis_scope",
                        "sample:base,com.lib.Base.call,call,(),method,REMOVED,true,P1,classfile_contract,api",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            risk_candidates_path.write_text(
                "\n".join(
                    [
                        "coord,api_name,api_simple,api_signature,symbol_kind,change_type,confirmed,severity,source,analysis_scope,candidate_bucket",
                        "sample:base,com.lib.Base,Base,,class,REMOVED,false,P1,candidate_scan,class_usage,system_source",
                        "sample:candidate,com.lib.Candidate,Candidate,,class,REMOVED,false,P1,candidate_scan,class_usage,system_source",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaises(run_step.StepError):
                run_step.materialize_step5_all_changed_apis_input(
                    all_changed_path,
                    report_dir,
                    {"step5_selected_coords": ["sample:candidate"]},
                )

            materialized_path, selection_summary = run_step.materialize_step5_all_changed_apis_input(
                all_changed_path, report_dir, {}
            )
            self.assertEqual(materialized_path, all_changed_path)
            self.assertEqual(len(selection_summary["matched_rows"]), 1)
            self.assertEqual(selection_summary["matched_rows"][0]["source"], "classfile_contract")
            scope = json.loads(
                (report_dir / ".runtime" / "cache" / "step5_selection.json").read_text(encoding="utf-8")
            )
            self.assertEqual(scope["mode"], "full")
            self.assertEqual(scope["included_dependency_count"], 1)

    def test_materialize_step5_input_name_filter_keeps_all_matching_coords(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            all_changed_path = report_dir / "all_changed_apis.csv"
            all_changed_path.write_text(
                "\n".join(
                    [
                        "coord,api_name,api_simple,api_signature,symbol_kind,change_type,confirmed,severity,source,analysis_scope",
                        "com.example:demo-lib,com.example.Demo.call,call,(),method,REMOVED,true,P1,classfile_contract,api",
                        "org.example:demo-lib,org.example.Demo.call,call,(),method,REMOVED,true,P1,classfile_contract,api",
                        "com.example:core-lib,com.example.Core.call,call,(),method,REMOVED,true,P1,classfile_contract,api",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            materialized_path, selection_summary = run_step.materialize_step5_all_changed_apis_input(
                all_changed_path,
                report_dir,
                {"step5_selected_names": ["demo-lib"]},
            )

            self.assertEqual(materialized_path.name, "selected_all_changed_apis.csv")
            self.assertEqual(selection_summary["matched_names"], ["demo-lib"])
            self.assertEqual(
                {row["coord"] for row in selection_summary["matched_rows"]},
                {"com.example:demo-lib", "org.example:demo-lib"},
            )
            scope = json.loads(
                (report_dir / ".runtime" / "cache" / "step5_selection.json").read_text(encoding="utf-8")
            )
            self.assertEqual(scope["mode"], "partial")
            self.assertEqual(scope["available_dependency_count"], 3)
            self.assertEqual(scope["included_dependency_count"], 2)
            self.assertEqual(scope["excluded_dependency_coords"], ["com.example:core-lib"])

    def test_apply_structured_user_response_bridges_response_without_pending_interaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step0"
            state["step0"]["input"] = {
                "base_branch": "base",
                "current_branch": "upgrade",
                "target_module": "mybatis-example",
            }
            args = SimpleNamespace(
                step="auto",
                response_json=json.dumps(
                    {
                        "intent_patch": {
                            "action": "continue",
                            "set": {
                                "target_module": ".",
                            },
                        }
                    },
                    ensure_ascii=False,
                ),
                response_file="",
            )
            result = run_step.apply_structured_user_response_if_present(
                args,
                project_dir,
                report_dir,
                state,
                "step0",
            )

            self.assertIsNone(result["early_exit_code"])
            self.assertEqual(result["step_id"], "step0")
            self.assertEqual(state["state"]["current_step"], "step0")
            self.assertEqual(state["step0"]["input"]["target_module"], ".")
            self.assertEqual(state["step0"]["input"]["primary_module"], ".")
            self.assertEqual(state["step0"]["input"]["modules"], ["."])
            self.assertEqual(state["state"]["last_user_response"]["step_id"], "step0")

    def test_apply_structured_user_response_infers_target_step_when_current_step_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            state["state"]["completed_step"] = "step6"
            state["step5"]["input"] = {
                "base_branch": "main",
                "current_branch": "feature/upgrade",
            }
            args = SimpleNamespace(
                step="auto",
                response_json=json.dumps(
                    {
                        "intent_patch": {
                            "action": "continue",
                            "set": {
                                "step5_selected_coords": ["com.example:demo-lib"],
                            },
                        }
                    },
                    ensure_ascii=False,
                ),
                response_file="",
            )

            result = run_step.apply_structured_user_response_if_present(
                args,
                project_dir,
                report_dir,
                state,
                "",
            )

            self.assertIsNone(result["early_exit_code"])
            self.assertEqual(result["step_id"], "step5")
            self.assertEqual(state["state"]["current_step"], "step5")
            self.assertEqual(
                state["step5"]["input"]["step5_selected_coords"],
                ["com.example:demo-lib"],
            )

    def test_apply_structured_user_response_resolves_selected_targets_without_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            self._api_changes_dir(report_dir).mkdir(parents=True, exist_ok=True)
            with (self._api_changes_dir(report_dir) / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=["coord", "class_name", "member"])
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "com.example:demo-lib",
                        "class_name": "com.example.Demo",
                        "member": "run()",
                    }
                )
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            args = SimpleNamespace(
                step="auto",
                response_json=json.dumps(
                    {
                        "intent_patch": {
                            "action": "continue",
                            "set": {
                                "selected_targets": ["com.example:demo-lib"],
                            },
                        }
                    },
                    ensure_ascii=False,
                ),
                response_file="",
            )

            result = run_step.apply_structured_user_response_if_present(
                args,
                project_dir,
                report_dir,
                state,
                "",
            )

            self.assertIsNone(result["early_exit_code"])
            self.assertEqual(result["step_id"], "step5")
            self.assertEqual(
                state["step5"]["input"]["step5_selected_coords"],
                ["com.example:demo-lib"],
            )

    def test_step4_checkpoint_uses_changed_dependencies_for_selection_options(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            api_dir = report_dir / "evidence" / "api_changes"
            api_dir.mkdir(parents=True, exist_ok=True)
            (api_dir / "changed_dependencies.csv").write_text(
                "selection_key,coord,dependency_name,changed_api_count,high_risk_api_count,business_exact_referenced_api_count,business_candidate_referenced_api_count,business_reference_occurrence_count,business_bytecode_scan_status,dependency_source_status,impact_priority_rank,change_types,symbol_kinds,recommended,review_focus,detail\n"
                "coord:com.acme:alpha,com.acme:alpha,alpha,42,5,2,1,4,complete,available,1,removed,method,true,业务最终制品直接引用 2 个变更 API,s4_per_dependency/com.acme__alpha/summary.json\n"
                "coord:com.acme:beta,com.acme:beta,beta,3,0,0,0,0,complete,unavailable,2,modified,method,true,未观察到业务字节码直接引用,s4_per_dependency/com.acme__beta/summary.json\n",
                encoding="utf-8",
            )

            selection_resolution = run_step.build_report_dir_step5_selection_resolution(report_dir)

            self.assertTrue(selection_resolution["enabled"])
            self.assertEqual(selection_resolution["options"][0]["selection_key"], "coord:com.acme:alpha")
            self.assertEqual(selection_resolution["options"][0]["coord"], "com.acme:alpha")
            self.assertEqual(selection_resolution["options"][0]["api_count"], 42)
            self.assertEqual(selection_resolution["options"][0]["high_risk_api_count"], 5)
            self.assertEqual(
                selection_resolution["options"][0][
                    "business_exact_referenced_api_count"
                ],
                2,
            )

            summary = run_step.build_step5_dependency_selection_summary(report_dir)
            self.assertEqual(summary["recommended_target_count"], 2)
            self.assertEqual(summary["recommended_targets"][0]["coord"], "com.acme:alpha")

            _, manifest_steps = run_step.load_manifest(ROOT_DIR / "scripts" / "step_manifest.json")
            interaction = run_step.build_interaction_payload(
                "step4",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )
            properties = interaction["response_schema"]["properties"]
            self.assertIn("分析范围", interaction["question"])
            self.assertIn("selected_targets", properties)
            self.assertNotIn("dependency_source_dirs", properties)
            self.assertNotIn("dependency_git_ref_overrides", properties)
            self.assertNotIn("step4_git_diff_timeout", properties)
            self.assertEqual(
                interaction["scope_preview"],
                {
                    "available_dependency_count": 2,
                    "total_api_count": 45,
                    "high_risk_api_count": 5,
                    "business_exact_referenced_api_count": 2,
                    "business_candidate_referenced_api_count": 1,
                    "partial_scope_effect": "未选择的变化依赖不会进入系统触达分析；最终报告只适用于所选范围。",
                },
            )
            self.assertEqual(
                interaction["files_to_review"],
                [str((api_dir / "changed_dependencies.md").resolve())],
            )
            card_text = "\n".join(interaction["user_decision_card"])
            self.assertIn("`com.acme:alpha`", card_text)
            self.assertIn("`com.acme:beta`", card_text)
            self.assertIn("完整依赖选择清单", card_text)
            self.assertIn("从“依赖包”列复制名称或完整坐标", card_text)
            self.assertNotIn("selected_targets", card_text)
            self.assertNotIn("selection_key", card_text)

    def test_step4_scope_checkpoint_is_skipped_when_no_real_scope_choice_exists(self):
        _, manifest_steps = run_step.load_manifest(ROOT_DIR / "scripts" / "step_manifest.json")
        for dependency_rows in (
            [],
            ["coord:com.acme:alpha,com.acme:alpha,alpha,1,1,removed,method,true,detail"],
        ):
            with self.subTest(candidate_count=len(dependency_rows)), tempfile.TemporaryDirectory() as tmp:
                project_dir = Path(tmp) / "project"
                report_dir = project_dir / ".upgrade-report"
                api_dir = report_dir / "evidence" / "api_changes"
                api_dir.mkdir(parents=True, exist_ok=True)
                (api_dir / "changed_dependencies.csv").write_text(
                    "selection_key,coord,dependency_name,changed_api_count,high_risk_api_count,change_types,symbol_kinds,recommended,detail\n"
                    + "\n".join(dependency_rows)
                    + ("\n" if dependency_rows else ""),
                    encoding="utf-8",
                )

                interaction = run_step.build_interaction_payload(
                    "step4",
                    report_dir,
                    manifest_steps,
                    project_dir,
                    run_context={},
                    main_state=run_step.new_main_state(report_dir),
                )

                self.assertIsNone(interaction)

    def test_report_landing_doc_is_single_dynamic_user_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            for relative in (
                "evidence/dependencies",
                "evidence/context",
                "evidence/static_scan",
                "evidence/api_changes",
                "evidence/call_chain",
            ):
                (report_dir / relative).mkdir(parents=True, exist_ok=True)

            for relative in (
                "deliverables/README.md",
                "evidence/README.md",
                ".runtime/README.md",
                "evidence/dependencies/README.md",
            ):
                path = report_dir / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("旧导航\n", encoding="utf-8")

            state = run_step.new_main_state(report_dir)
            state["state"].update(
                {
                    "current_step": "step5",
                    "completed_step": "step4",
                    "status": "awaiting_user_input",
                    "blocking_reason": "请确认系统触达证据的分析范围。",
                    "pending_interaction": {
                        "question": "请选择全量分析或部分分析。",
                        "options": [
                            {"id": "continue", "label": "全量分析"},
                            {"id": "continue_with_selection", "label": "部分分析"},
                        ],
                        "selection_options": [{"coord": "com.acme:alpha"}],
                        "files_to_review": [
                            str(report_dir / "evidence" / "api_changes" / "changed_dependencies.md")
                        ],
                    },
                }
            )
            (report_dir / "evidence" / "api_changes" / "changed_dependencies.md").write_text(
                "# 变化依赖\n", encoding="utf-8"
            )
            run_step.write_report_landing_docs(report_dir, state)

            root_readme = (report_dir / "README.md").read_text(encoding="utf-8")
            self.assertIn("当前状态：等待你确认", root_readme)
            self.assertIn("当前任务：系统触达证据", root_readme)
            self.assertIn("请确认系统触达证据的分析范围", root_readme)
            self.assertIn("## 当前需要你决定", root_readme)
            self.assertIn("请选择全量分析或部分分析", root_readme)
            self.assertIn("`全量分析`", root_readme)
            self.assertIn("完整依赖选择清单（包含未展示候选）", root_readme)
            self.assertIn("从“依赖包”列复制名称或完整坐标", root_readme)
            self.assertIn(
                "[evidence/api_changes/changed_dependencies.md](evidence/api_changes/changed_dependencies.md)",
                root_readme,
            )
            self.assertNotIn("deliverables/report.md", root_readme)
            self.assertNotIn("Step1", root_readme)
            self.assertNotIn("Step5", root_readme)
            self.assertEqual((report_dir / "deliverables" / "README.md").read_text(encoding="utf-8"), "旧导航\n")
            self.assertEqual((report_dir / "evidence" / "README.md").read_text(encoding="utf-8"), "旧导航\n")
            self.assertEqual((report_dir / ".runtime" / "README.md").read_text(encoding="utf-8"), "旧导航\n")
            self.assertEqual((report_dir / "evidence" / "dependencies" / "README.md").read_text(encoding="utf-8"), "旧导航\n")

    def test_user_runtime_messages_cover_start_completion_and_failure_without_internal_state(self):
        start = "\n".join(run_step.build_user_runtime_message("start", "step3"))
        complete = "\n".join(run_step.build_user_runtime_message("complete", "step3"))
        finished = "\n".join(run_step.build_user_runtime_message("complete", "step6"))
        failed = "\n".join(run_step.build_user_runtime_message("failed", "step4", reason="无法读取依赖包"))

        self.assertIn("正在分析：兼容性线索", start)
        self.assertIn("兼容性线索已完成", complete)
        self.assertIn("接下来：依赖 API 变化", complete)
        self.assertIn("分析已完成", finished)
        self.assertIn("deliverables/report.md", finished)
        self.assertIn("依赖 API 变化未完成", failed)
        self.assertIn("无法读取依赖包", failed)
        self.assertIn("系统已停止当前任务", failed)
        self.assertIn("已有证据会保留", failed)
        for text in (start, complete, finished, failed):
            self.assertNotRegex(text, r"\b[Ss]tep\d+\b")
            self.assertNotIn("main_state", text)
            self.assertNotIn("退出码", text)

    def test_completed_step_publishes_compact_resume_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            output = (
                report_dir
                / "evidence"
                / "static_scan"
                / "s3_jdk_removed_api.csv"
            )
            output.parent.mkdir(parents=True)
            output.write_text("api\n", encoding="utf-8")
            state = run_step.new_main_state(report_dir)

            run_step.persist_completed_step(
                state,
                "step3",
                report_dir,
                {"project_scope": {}},
            )

            summary_path = run_step.last_step_summary_path(report_dir)
            summary_bytes = summary_path.read_bytes()
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            resume_text = run_step.resume_context_path(report_dir).read_text(
                encoding="utf-8"
            )
            coverage_path = (
                report_dir / ".runtime" / "coverage" / "coverage.json"
            )
            coverage = json.loads(
                coverage_path.read_text(encoding="utf-8")
            )
            nested_coverage_exists = (
                report_dir
                / ".runtime"
                / "coverage"
                / ".runtime"
                / "coverage"
                / "coverage.json"
            ).exists()

        self.assertFalse(summary_bytes.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(summary["event"], "step_completed")
        self.assertEqual(summary["last_step"]["step_id"], "step3")
        self.assertTrue(summary["last_step"]["completed"])
        self.assertEqual(summary["workflow_state"]["current_step"], "step4")
        self.assertFalse(summary["needs_user_input"])
        self.assertIn(
            "evidence/static_scan/s3_jdk_removed_api.csv",
            summary["outputs"],
        )
        self.assertIn("## 可直接转述的状态", resume_text)
        self.assertIn("兼容性线索", resume_text)
        self.assertIn("继续执行依赖 API 变化", resume_text)
        self.assertEqual(
            coverage["schema"], "java-upgrade-analyzer.coverage.v1"
        )
        self.assertFalse(nested_coverage_exists)

    def test_interactive_step_writes_coverage_below_report_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            interaction = {
                "step_id": "step3",
                "status": "awaiting_user_input",
                "question": "请确认兼容性线索。",
            }

            run_step.persist_step_interaction(
                state,
                "step3",
                report_dir,
                {"project_scope": {}},
                interaction,
            )
            coverage_path = (
                report_dir / ".runtime" / "coverage" / "coverage.json"
            )
            nested_coverage = (
                report_dir
                / ".runtime"
                / "coverage"
                / ".runtime"
                / "coverage"
                / "coverage.json"
            )
            coverage_exists = coverage_path.is_file()
            nested_coverage_exists = nested_coverage.exists()

        self.assertTrue(coverage_exists)
        self.assertFalse(nested_coverage_exists)

    def test_completed_checkpoint_snapshot_names_required_user_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            interaction = {
                "step_id": "step4",
                "status": "awaiting_user_input",
                "question": "请选择全量分析或指定依赖。",
                "options": [{"id": "continue", "label": "全量分析"}],
            }

            run_step.persist_step_interaction(
                state,
                "step4",
                report_dir,
                {"project_scope": {}},
                interaction,
            )
            summary = run_step.read_json(
                run_step.last_step_summary_path(report_dir)
            )
            resume_text = run_step.resume_context_path(report_dir).read_text(
                encoding="utf-8"
            )

        self.assertEqual(summary["event"], "step_completed_awaiting_user")
        self.assertTrue(summary["last_step"]["completed"])
        self.assertTrue(summary["needs_user_input"])
        self.assertEqual(
            summary["user_input"]["question"],
            "请选择全量分析或指定依赖。",
        )
        self.assertIn("是否需要用户输入：是", resume_text)
        self.assertIn("请选择全量分析或指定依赖", resume_text)

    def test_environment_block_message_names_only_failed_prerequisites_and_preserves_business_input(self):
        text = "\n".join(
            run_step.build_environment_block_message(
                {
                    "status": "failed",
                    "checks": [
                        {
                            "component": "python",
                            "status": "passed",
                            "observed": "CPython 3.12.9",
                            "expected": "CPython 3.10 or newer",
                        },
                        {
                            "component": "tool:mvn",
                            "status": "failed",
                            "observed": "未检测到",
                            "expected": "installed and executable",
                        },
                    ],
                }
            )
        )

        self.assertIn("命令行工具 mvn", text)
        self.assertNotIn("Python 运行时：", text)
        self.assertIn("业务输入和分析范围无需修改", text)
        self.assertNotIn("action=", text)

    def test_environment_warning_explains_unverified_python_without_blocking(self):
        lines = run_step.build_environment_warning_messages(
            {
                "status": "passed",
                "warnings": [
                    {
                        "component": "python",
                        "status": "warning",
                        "observed": "CPython 3.11.9",
                        "expected": "CPython 3.10 or newer",
                        "reason": "python_version_not_ci_verified",
                    }
                ],
            }
        )

        self.assertEqual(len(lines), 1)
        self.assertIn("满足最低运行要求", lines[0])
        self.assertIn("尚未进入 CI 验证矩阵", lines[0])

    def test_final_completion_summary_marks_partial_scope_and_uncertainty_as_limited(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            findings_path = report_dir / ".runtime" / "findings" / "s6_findings.json"
            findings_path.parent.mkdir(parents=True)
            findings_path.write_text(
                json.dumps(
                    {
                        "coverage": {"overall_status": "complete"},
                        "analysis_scope": {
                            "mode": "partial",
                            "included_dependency_count": 1,
                            "analyzed_dependency_count": 0,
                            "available_dependency_count": 3,
                            "included_api_count": 7,
                            "analyzed_api_count": 2,
                            "total_api_count": 19,
                            "included_dependency_coords": [
                                "com.example:demo"
                            ],
                            "excluded_dependency_coords": [
                                "com.example:other",
                                "com.example:third",
                            ],
                        },
                        "dependency_changes": [
                            {
                                "coord": "com.example:demo",
                                "old_version": "1.0.0",
                                "new_version": "2.0.0",
                                "change_type": "major",
                            },
                            {
                                "coord": "com.example:other",
                                "old_version": "1.0.0",
                                "new_version": "2.0.0",
                                "change_type": "major",
                            },
                            {
                                "coord": "com.example:third",
                                "old_version": "1.0.0",
                                "new_version": "2.0.0",
                                "change_type": "major",
                            },
                        ],
                        "changed_api_inventory": [
                            {
                                "coord": "com.example:demo",
                                "api": (
                                    "com.example.Api.confirmed"
                                    if index == 0
                                    else (
                                        "com.example.Api.uncertain"
                                        if index == 1
                                        else f"com.example.Api.pending{index}"
                                    )
                                ),
                                "api_signature": "()",
                                "symbol_kind": "method",
                                "change_type": "REMOVED",
                            }
                            for index in range(7)
                        ],
                        "probable_impact": [{
                            "coord": "com.example:demo",
                            "api": "com.example.Api.probable",
                            "api_signature": "()",
                            "symbol_kind": "method",
                            "change_type": "REMOVED",
                        }],
                        "uncertain": [{
                            "coord": "com.example:demo",
                            "api": "com.example.Api.uncertain",
                            "api_signature": "()",
                            "symbol_kind": "method",
                            "change_type": "REMOVED",
                        }],
                        "not_analyzed": [],
                        "diagnostics": [],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            summary = run_step.build_final_completion_summary(report_dir)
            message = "\n".join(
                run_step.build_user_runtime_message(
                    "complete", "step6", completion_summary=summary
                )
            )

        self.assertEqual(summary["status"], "completed_with_limits")
        self.assertEqual(summary["probable_count"], 1)
        self.assertIn("用户选择了部分变化依赖", summary["limitations"])
        self.assertIn("1 项存在候选证据但结论未确定", summary["limitations"])
        self.assertIn("分析已完成，但存在结论限制", message)
        for limitation in summary["limitations"]:
            self.assertIn(limitation, message)
        self.assertIn("部分依赖（1/3）", message)
        self.assertEqual(summary["dependency_total_count"], 1)
        self.assertEqual(summary["dependency_completed_count"], 0)
        self.assertEqual(summary["dependency_incomplete_count"], 1)
        self.assertEqual(summary["dependency_probable_count"], 1)
        self.assertEqual(summary["api_total_count"], 7)
        self.assertEqual(summary["api_completed_count"], 2)
        self.assertEqual(summary["api_incomplete_count"], 5)
        self.assertEqual(summary["api_probable_count"], 1)
        self.assertIn(
            "依赖：变化 1，已完成分析 0，未完成分析 1，其中可能影响 1。",
            message,
        )
        self.assertIn(
            "API：变化 7，已完成分析 2，未完成分析 5，可能影响 1。",
            message,
        )
        self.assertIn(
            "deliverables/all-affected-dependencies.md",
            message,
        )
        self.assertIn(
            "deliverables/all-affected-dependencies.csv",
            message,
        )
        self.assertIn("deliverables/all-impact-details.md", message)
        self.assertIn("deliverables/all-impact-details.csv", message)
        self.assertNotIn("deliverables/analysis-scope.md", message)

    def test_final_completion_separates_candidate_uncertainty_from_analysis_limitations(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            findings_path = run_step.s6_findings_path(report_dir)
            findings_path.parent.mkdir(parents=True)
            findings_path.write_text(
                json.dumps({
                    "coverage": {"overall_status": "complete"},
                    "analysis_scope": {"mode": "full"},
                    "probable_impact": [],
                    "uncertain": [
                        {"uncertainty_kind": "candidate_evidence"},
                        {"uncertainty_kind": "analysis_limitation"},
                    ],
                    "not_analyzed": [], "diagnostics": [],
                }, ensure_ascii=False),
                encoding="utf-8",
            )

            summary = run_step.build_final_completion_summary(report_dir)

        self.assertEqual(summary["uncertain_count"], 2)
        self.assertEqual(summary["uncertain_candidate_count"], 1)
        self.assertEqual(summary["uncertain_analysis_limitation_count"], 1)
        self.assertIn(
            "1 项存在候选证据但结论未确定",
            summary["limitations"],
        )
        self.assertIn(
            "1 项受静态分析能力边界限制，未发现候选调用证据且结论未确定",
            summary["limitations"],
        )

    def test_landing_status_does_not_hide_completion_limits(self):
        state = {
            "state": {
                "current_step": "done",
                "status": "completed_with_limits",
            }
        }

        text = "\n".join(run_step._landing_status_lines(state))

        self.assertIn("分析已完成，但存在结论限制", text)
        self.assertIn("结论适用范围以本轮分析范围为边界", text)
        self.assertNotIn("请先", text)

    def test_completed_landing_page_links_only_existing_outputs_and_shows_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            deliverables = report_dir / "deliverables"
            deliverables.mkdir(parents=True)
            (deliverables / "report.md").write_text("# 报告\n", encoding="utf-8")
            (deliverables / "all-affected-dependencies.md").write_text(
                "# 完整依赖分析\n",
                encoding="utf-8",
            )
            (deliverables / "all-affected-dependencies.csv").write_text(
                "依赖,分析结果\n",
                encoding="utf-8",
            )
            (deliverables / "all-impact-details.md").write_text(
                "# 完整 API 与调用关系\n",
                encoding="utf-8",
            )
            (deliverables / "all-impact-details.csv").write_text(
                "依赖,API,分析结果\n",
                encoding="utf-8",
            )
            (deliverables / "analysis-scope.md").write_text("# 范围\n", encoding="utf-8")
            state = run_step.new_main_state(report_dir)
            state["state"].update(
                {
                    "current_step": "done",
                    "completed_step": "step6",
                    "status": "completed_with_limits",
                    "completion_summary": {
                        "scope_mode": "partial",
                        "included_dependency_count": 1,
                        "available_dependency_count": 3,
                        "probable_count": 1,
                        "uncertain_count": 4,
                        "not_analyzed_count": 0,
                        "dependency_total_count": 3,
                        "dependency_completed_count": 2,
                        "dependency_incomplete_count": 1,
                        "dependency_probable_count": 1,
                        "api_total_count": 10,
                        "api_completed_count": 7,
                        "api_incomplete_count": 3,
                        "api_probable_count": 1,
                        "limitations": ["用户选择了部分变化依赖"],
                    },
                }
            )

            run_step.write_report_landing_docs(report_dir, state)
            text = (report_dir / "README.md").read_text(encoding="utf-8")

        self.assertIn("分析范围：部分依赖（1/3）", text)
        self.assertIn(
            "依赖：变化 3，已完成分析 2，未完成分析 1，其中可能影响 1。",
            text,
        )
        self.assertIn(
            "API：变化 10，已完成分析 7，未完成分析 3，可能影响 1。",
            text,
        )
        self.assertIn("结论限制：用户选择了部分变化依赖", text)
        self.assertIn("[deliverables/report.md](deliverables/report.md)", text)
        self.assertIn(
            "[deliverables/all-affected-dependencies.md]"
            "(deliverables/all-affected-dependencies.md)",
            text,
        )
        self.assertIn(
            "[deliverables/all-impact-details.md]"
            "(deliverables/all-impact-details.md)",
            text,
        )
        self.assertIn(
            "[deliverables/all-affected-dependencies.csv]"
            "(deliverables/all-affected-dependencies.csv)",
            text,
        )
        self.assertIn(
            "[deliverables/all-impact-details.csv]"
            "(deliverables/all-impact-details.csv)",
            text,
        )
        self.assertIn(
            "[deliverables/analysis-scope.md](deliverables/analysis-scope.md)", text
        )
        self.assertNotIn("evidence/dependencies/dep_changes.csv", text)

    def test_final_completion_counts_binary_not_analyzed_items_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            findings_path = report_dir / ".runtime" / "findings" / "s6_findings.json"
            findings_path.parent.mkdir(parents=True)
            probable = {
                "coord": "com.example:demo",
                "api": "com.example.Api.probable",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "可能影响",
            }
            needs_input = {
                "coord": "com.example:demo",
                "api": "com.example.Api.needsInput",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "需要补充输入",
            }
            residual = {
                "coord": "com.example:demo",
                "api": "com.example.Api.notAnalyzed",
                "api_signature": "()",
                "symbol_kind": "method",
                "change_type": "REMOVED",
                "user_conclusion": "当前无法确认",
            }
            findings_path.write_text(
                json.dumps(
                    {
                        "coverage": {"overall_status": "complete"},
                        "analysis_scope": {
                            "mode": "full",
                            "included_dependency_count": 1,
                            "analyzed_dependency_count": 0,
                            "available_dependency_count": 1,
                            "included_api_count": 3,
                            "analyzed_api_count": 1,
                            "total_api_count": 3,
                        },
                        "probable_impact": [probable],
                        "uncertain": [],
                        "not_analyzed": [needs_input, residual],
                        "diagnostics": [],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            summary = run_step.build_final_completion_summary(report_dir)
            terminal = "\n".join(
                run_step.build_user_runtime_message(
                    "complete", "step6", completion_summary=summary
                )
            )
            landing = "\n".join(
                run_step._landing_status_lines(
                    {
                        "state": {
                            "current_step": "done",
                            "status": summary["status"],
                            "completion_summary": summary,
                        }
                    }
                )
            )

        self.assertEqual(summary["probable_count"], 1)
        self.assertNotIn("needs_input_count", summary)
        self.assertEqual(summary["not_analyzed_count"], 2)
        self.assertEqual(summary["dependency_total_count"], 1)
        self.assertEqual(summary["dependency_completed_count"], 0)
        self.assertEqual(summary["dependency_incomplete_count"], 1)
        self.assertEqual(summary["dependency_probable_count"], 1)
        self.assertEqual(summary["api_total_count"], 3)
        self.assertEqual(summary["api_completed_count"], 1)
        self.assertEqual(summary["api_incomplete_count"], 2)
        self.assertEqual(summary["api_probable_count"], 1)
        for text in (terminal, landing):
            self.assertIn(
                "依赖：变化 1，已完成分析 0，未完成分析 1，其中可能影响 1。",
                text,
            )
            self.assertIn(
                "API：变化 3，已完成分析 1，未完成分析 2，可能影响 1。",
                text,
            )
            self.assertNotIn("建议", text)
            self.assertNotIn("下一步", text)

    def test_later_action_persists_paused_user_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            interaction = {
                "step_id": "step4",
                "status": "awaiting_user_input",
                "options": [
                    {"id": "continue", "label": "全量继续"},
                    {"id": "cancel", "label": "稍后处理"},
                ],
            }
            state["state"].update(
                {
                    "current_step": "step5",
                    "completed_step": "step4",
                    "status": "awaiting_user_input",
                    "pending_interaction": interaction,
                }
            )
            run_step.save_main_state(report_dir, state)
            args = SimpleNamespace(
                response_json=json.dumps({"action": "cancel"}, ensure_ascii=False),
                response_file="",
            )

            result = run_step.apply_structured_user_response_if_present(
                args,
                project_dir,
                report_dir,
                state,
                "step5",
            )
            saved = run_step.load_main_state(report_dir)
            landing = (report_dir / "README.md").read_text(encoding="utf-8")

        self.assertEqual(result["early_exit_code"], 0)
        self.assertEqual(saved["state"]["status"], "paused_by_user")
        self.assertEqual(saved["state"]["current_step"], "step5")
        self.assertEqual(saved["state"]["pending_interaction"]["step_id"], "step4")
        self.assertIn("当前状态：已暂停", landing)
        self.assertIn("已保留：依赖 API 变化及之前的正式产物", landing)
        self.assertIn("恢复后：从系统触达证据继续，不重复已完成任务", landing)
        self.assertIn("再次运行分析时，会回到当前确认任务", landing)

    def test_user_decision_card_hides_internal_fields_and_shows_direct_replies(self):
        interaction = {
            "step_id": "step4",
            "question": "Step5 是全量分析，还是只分析部分依赖包？",
            "recommended_action": "依赖包数量不多时，选择全量继续。",
            "options": [
                {"id": "continue", "label": "全量继续"},
                {"id": "rerun_current_step", "label": "补材料后重跑"},
            ],
            "selection_options": [
                {
                    "selection_key": "coord:com.acme:alpha",
                    "coord": "com.acme:alpha",
                    "api_count": 42,
                    "high_risk_api_count": 5,
                    "business_exact_referenced_api_count": 3,
                    "business_candidate_referenced_api_count": 1,
                    "business_reference_occurrence_count": 7,
                    "dependency_source_status": "available",
                    "impact_priority_rank": 1,
                    "recommendation_reason": "业务最终制品直接引用 3 个变更 API",
                }
            ],
            "selection_resolution": {"enabled": True},
            "action_requirements": {"continue": {"required_fields": []}},
            "files_to_review": ["/tmp/.upgrade-report/evidence/api_changes/changed_dependencies.md"],
        }

        lines = run_step.build_user_decision_card(interaction)
        text = "\n".join(lines)

        self.assertIn("当前需要确认：系统触达证据是覆盖全部依赖，还是只分析部分依赖包？", text)
        self.assertIn("推荐动作：依赖包数量不多时，选择全量继续。", text)
        self.assertIn("`com.acme:alpha`", text)
        self.assertIn("直接回复依赖名称或完整坐标", text)
        self.assertIn("完整依赖选择清单", text)
        self.assertIn("你可以直接回复：", text)
        self.assertNotIn("Step5", text)
        self.assertNotIn("selected_targets", text)
        self.assertNotIn("`continue`", text)
        self.assertNotIn("`rerun_current_step`", text)
        self.assertNotIn("coord:com.acme:alpha", text)
        self.assertNotIn("action_requirements", text)
        self.assertNotIn("selection_resolution", text)

    def test_dependency_selection_card_names_full_list_when_candidates_are_truncated(self):
        all_candidates = [
            {
                "selection_key": f"coord:com.acme:lib-{index}",
                "coord": f"com.acme:lib-{index}",
                "api_count": index + 1,
                "high_risk_api_count": index % 3,
                "business_exact_referenced_api_count": max(10 - index, 0),
                "business_candidate_referenced_api_count": 0,
                "business_reference_occurrence_count": max(10 - index, 0),
                "dependency_source_status": "available" if index % 2 else "unavailable",
                "impact_priority_rank": index + 1,
                "recommendation_reason": f"优先级依据 {index + 1}",
                "recommended": index < 10,
            }
            for index in range(37)
        ]
        interaction = {
            "step_id": "step4",
            "question": "请选择系统触达证据的分析范围。",
            "options": [{"id": "continue", "label": "全部分析"}],
            "selection_options": all_candidates[:10],
            "recommended_selection_options": all_candidates[:10],
            "recommended_candidate_count": 10,
            "selection_resolution": {
                "enabled": True,
                "options": all_candidates,
                "source_file": "/project/.upgrade-report/evidence/api_changes/changed_dependencies.md",
            },
            "files_to_review": [
                "/project/.upgrade-report/evidence/api_changes/changed_dependencies.md",
                "/project/.upgrade-report/evidence/api_changes/all_changed_apis.csv",
                "/project/.upgrade-report/evidence/api_changes/summary.txt",
                "/project/.upgrade-report/evidence/api_changes/git_ref_matches.txt",
                "/project/.upgrade-report/evidence/api_changes/timeouts.json",
                "/project/.upgrade-report/evidence/api_changes/all_changed_apis_part_001.csv",
                "/project/.upgrade-report/evidence/api_changes/all_changed_apis_part_002.csv",
            ],
        }

        text = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertIn("覆盖全部 37 个变化依赖", text)
        self.assertIn("Top 10 影响复核优先项，展示 10 / 10 个", text)
        self.assertIn("精确直接引用 API", text)
        self.assertIn("删除、签名变化等变更类型不额外加权", text)
        self.assertIn("依赖源码是否可用只展示分析条件，不参与影响排序", text)
        self.assertIn("其余 27 个候选未在卡片中展开", text)
        self.assertIn(
            "该文件不是普通复核材料；需要选择未展示的依赖时",
            text,
        )
        self.assertNotIn("selected_targets", text)
        self.assertNotIn("完整候选请看下面的文件", text)
        self.assertNotIn("interaction.json", text)
        self.assertIn("all_changed_apis_part_002.csv", text)

    def test_dependency_selection_card_explains_how_to_select_from_full_list(self):
        interaction = {
            "step_id": "step4",
            "question": "请选择系统触达证据的分析范围。",
            "options": [
                {"id": "continue", "label": "继续（全量分析）"},
            ],
            "selection_options": [
                {
                    "selection_key": "coord:com.acme:alpha",
                    "coord": "com.acme:alpha",
                    "api_count": 42,
                    "high_risk_api_count": 5,
                    "business_exact_referenced_api_count": 3,
                    "business_candidate_referenced_api_count": 1,
                    "business_reference_occurrence_count": 7,
                    "dependency_source_status": "available",
                    "impact_priority_rank": 1,
                    "recommendation_reason": "业务最终制品直接引用 3 个变更 API",
                }
            ],
            "recommended_selection_options": [
                {
                    "selection_key": "coord:com.acme:alpha",
                    "coord": "com.acme:alpha",
                    "api_count": 42,
                    "high_risk_api_count": 5,
                    "business_exact_referenced_api_count": 3,
                    "business_candidate_referenced_api_count": 1,
                    "business_reference_occurrence_count": 7,
                    "dependency_source_status": "available",
                    "impact_priority_rank": 1,
                    "recommendation_reason": "业务最终制品直接引用 3 个变更 API",
                }
            ],
            "recommended_candidate_count": 1,
            "selection_resolution": {
                "enabled": True,
                "options": [
                    {
                        "selection_key": "coord:com.acme:alpha",
                        "coord": "com.acme:alpha",
                    },
                    {
                        "selection_key": "coord:com.acme:beta",
                        "coord": "com.acme:beta",
                    },
                ],
            },
            "files_to_review": [
                "/project/.upgrade-report/evidence/api_changes/changed_dependencies.md",
            ],
        }

        text = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertIn("请选择分析范围：", text)
        self.assertIn("1. 全量分析", text)
        self.assertIn("覆盖全部 2 个变化依赖", text)
        self.assertIn("2. 部分分析（仅在明确控制耗时时）", text)
        self.assertIn("Top 1 影响复核优先项，展示 1 / 1 个", text)
        self.assertIn("先比较业务最终制品精确直接引用的变更 API 数", text)
        self.assertIn("不表示系统建议缩小范围，也不代表已经确认有影响", text)
        self.assertIn("| 1 | `com.acme:alpha` | 3 | 1 | 7 | 42 | 可用 |", text)
        self.assertIn(
            "完整依赖选择清单：`/project/.upgrade-report/evidence/api_changes/changed_dependencies.md`",
            text,
        )
        self.assertIn("从“依赖包”列复制名称或完整坐标", text)
        self.assertIn("只分析 com.acme:alpha", text)
        self.assertNotIn("selected_targets", text)

    def test_terminal_pause_message_only_shows_user_facing_decision_information(self):
        interaction = {
            "step_id": "step4",
            "title": "jar 包变更对比",
            "question": "请确认依赖 API 变化是否完整。",
            "hard_stop": True,
            "runtime_rules": ["must_wait_for_user_reply"],
            "next_action_rule": "resume_only",
            "resume_command_examples": [{"label": "continue", "command": "python run_step.py --response-json ..."}],
            "options": [
                {"id": "continue", "label": "结果完整，继续分析"},
                {"id": "rerun_current_step"},
            ],
            "files_to_review": ["/tmp/.upgrade-report/evidence/api_changes/changed_dependencies.md"],
        }
        stderr = io.StringIO()
        stdout = io.StringIO()

        with patch.object(sys, "stderr", stderr), patch.object(sys, "stdout", stdout):
            run_step.print_interaction_to_streams(interaction, Path("/tmp/.upgrade-report"))

        text = stderr.getvalue()
        self.assertIn("依赖 API 变化", text)
        self.assertIn("为什么暂停", text)
        self.assertIn("结果完整，继续分析", text)
        self.assertIn("补充信息后重新分析", text)
        self.assertIn("你可以直接回复", text)
        self.assertIn("changed_dependencies.md", text)
        for internal_text in (
            "AWAITING USER INPUT",
            "HARD STOP",
            "RULE:",
            "NEXT ACTION ONLY",
            "continue`",
            "rerun_current_step",
            "interaction.json",
            "main_state",
            "response_schema",
            "--response-json",
        ):
            self.assertNotIn(internal_text, text)
        machine_line = next(line for line in stdout.getvalue().splitlines() if line.startswith("JUA_CONFIRMATION_JSON:"))
        machine_event = json.loads(machine_line.split(":", 1)[1])
        self.assertEqual(machine_event["schema"], "java-upgrade-analyzer.confirmation.v1")
        self.assertEqual(machine_event["event"], "interaction_required")
        self.assertEqual(
            machine_event["user_decision_card"],
            run_step.build_user_decision_card(interaction),
        )
        self.assertNotIn(
            "selected_targets",
            "\n".join(machine_event["user_decision_card"]),
        )
        self.assertNotIn("fallback_inputs", machine_event)

    def test_human_interaction_output_mode_hides_machine_protocol(self):
        interaction = {
            "step_id": "step4",
            "question": "请选择分析范围。",
            "options": [{"id": "continue", "label": "全量继续"}],
        }
        stderr = io.StringIO()
        stdout = io.StringIO()

        with patch.dict(os.environ, {"JUA_INTERACTION_OUTPUT": "human"}), \
                patch.object(sys, "stderr", stderr), patch.object(sys, "stdout", stdout):
            run_step.print_interaction_to_streams(interaction, Path("/tmp/.upgrade-report"))

        self.assertIn("请选择分析范围", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_user_task_names_and_manifest_checkpoint_copy_are_human_facing(self):
        expected_names = {
            "step0": "正式分析信息确认",
            "step1": "分析对象与依赖范围",
            "step2": "升级上下文",
            "step3": "兼容性线索",
            "step4": "依赖 API 变化",
            "step5": "系统触达证据",
            "step6": "分析报告",
        }
        self.assertEqual(run_step.USER_TASK_NAMES, expected_names)

        manifest = json.loads((ROOT_DIR / "scripts" / "step_manifest.json").read_text(encoding="utf-8"))
        for step in manifest["steps"]:
            self.assertEqual(step["title"], expected_names[step["id"]])
            interaction = step.get("interaction")
            if not interaction:
                continue
            visible_copy = [interaction.get("question", "")]
            visible_copy.extend(option.get("description", "") for option in interaction.get("options", []))
            for copy in visible_copy:
                self.assertIsNone(re.search(r"\bStep\d+\b|\bstep\d+\b", copy), copy)
                self.assertNotIn("action=", copy)
                self.assertNotIn("_step", copy)

    def test_step4_checkpoint_points_dependency_selection_to_markdown_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            api_dir = self._api_changes_dir(report_dir)
            api_dir.mkdir(parents=True)
            with (api_dir / "changed_dependencies.csv").open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["selection_key", "coord", "name", "api_count", "high_risk_api_count", "change_types"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "selection_key": "coord:com.example:demo-lib",
                        "coord": "com.example:demo-lib",
                        "name": "demo-lib",
                        "api_count": "42",
                        "high_risk_api_count": "5",
                        "change_types": "REMOVED",
                    }
                )
            (api_dir / "all_changed_apis.csv").write_text(
                "coord,api_name,api_signature,symbol_kind,change_type,severity\n"
                "com.example:demo-lib,com.example.Demo.removed,(),method,REMOVED,P1\n",
                encoding="utf-8",
            )
            manifest_steps = {
                "step4": {
                    "title": "API 变化分析",
                    "interaction": {
                        "type": "review",
                        "question": "Step5 是全量分析，还是只分析部分依赖包？",
                        "options": [{"id": "continue", "label": "继续"}],
                    },
                    "outputs": ["evidence/api_changes/all_changed_apis.csv"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step4",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        checklist_text = "\n".join(payload.get("checklist_lines") or [])
        review_files = "\n".join(payload.get("files_to_review") or [])
        self.assertIn("完整依赖包清单见 changed_dependencies.md", checklist_text)
        self.assertIn("API 级明细不作为普通选择入口", checklist_text)
        self.assertIn("changed_dependencies.md", review_files)
        self.assertNotIn("summary.txt", review_files)
        self.assertNotIn("git_ref_matches.txt", review_files)
        self.assertNotIn("all_changed_apis.csv", review_files)

    def test_user_decision_card_covers_step0_unified_confirmation(self):
        interaction = run_step.build_step0_confirmation_interaction({})

        lines = run_step.build_user_decision_card(interaction)
        text = "\n".join(lines)

        self.assertIn("| 信息 | Base | Current |", text)
        self.assertIn("| 最终制品 |", text)
        self.assertIn("| 版本分支 |", text)
        self.assertIn("| 应用源码 |", text)
        self.assertIn("| 依赖包源码 |", text)
        self.assertIn("同一回复中一次补齐", text)
        self.assertNotIn("response_schema", text)
        self.assertNotIn("input_normalization", text)
        self.assertNotIn("action_requirements", text)


    def test_user_decision_card_humanizes_option_descriptions(self):
        interaction = {
            "step_id": "step5",
            "question": "请选择后续处理方式。",
            "options": [
                {
                    "id": "restart_from_step",
                    "label": "从指定步骤重跑",
                    "description": "若需要回到更早步骤修正输入，可指定 restart_step_id 后重跑。",
                },
                {
                    "id": "rerun_current_step",
                    "label": "降级后重跑",
                    "description": "相关 API 将标记为 not_analyzed。",
                },
            ],
        }

        text = "\n".join(run_step.build_user_decision_card(interaction))

        self.assertIn("重跑起始步骤", text)
        self.assertIn("本次未完成分析", text)
        self.assertNotIn("restart_step_id", text)
        self.assertNotIn("not_analyzed", text)


    def test_apply_structured_user_response_resolves_name_selected_targets_without_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            self._api_changes_dir(report_dir).mkdir(parents=True, exist_ok=True)
            with (self._api_changes_dir(report_dir) / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=["coord", "class_name", "member"])
                writer.writeheader()
                writer.writerow({"coord": "com.example:demo-lib", "class_name": "a.A", "member": "m()"})
                writer.writerow({"coord": "org.example:demo-lib", "class_name": "b.B", "member": "m()"})
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            args = SimpleNamespace(
                step="auto",
                response_json=json.dumps(
                    {
                        "intent_patch": {
                            "action": "continue",
                            "set": {
                                "selected_targets": ["demo-lib"],
                            },
                        }
                    },
                    ensure_ascii=False,
                ),
                response_file="",
            )

            result = run_step.apply_structured_user_response_if_present(
                args,
                project_dir,
                report_dir,
                state,
                "",
            )

            self.assertIsNone(result["early_exit_code"])
            self.assertEqual(result["step_id"], "step5")
            self.assertEqual(
                state["step5"]["input"]["step5_selected_names"],
                ["demo-lib"],
            )

    def test_build_canonical_user_response_supports_intent_patch(self):
        canonical = run_step.build_canonical_user_response(
            {
                "intent_patch": {
                    "action": "restart_from_step",
                    "set": {
                        "dependency_source_dirs": ["dep-repo"],
                    },
                    "restart_step_id": "step2",
                    "notes": "修正源码目录后从 step2 重跑",
                }
            }
        )

        self.assertEqual(canonical["action"], "restart_from_step")
        self.assertEqual(canonical["dependency_source_dirs"], ["dep-repo"])
        self.assertEqual(canonical["restart_step_id"], "step2")
        self.assertEqual(canonical["notes"], "修正源码目录后从 step2 重跑")
        self.assertIn("__intent_patch", canonical)

    def test_build_canonical_user_response_hoists_restart_step_from_set(self):
        canonical = run_step.build_canonical_user_response(
            {
                "intent_patch": {
                    "action": "restart_from_step",
                    "set": {"restart_step_id": "step2"},
                }
            }
        )

        self.assertEqual(canonical["restart_step_id"], "step2")
        self.assertEqual(canonical["__intent_patch"]["set"], {})
        self.assertEqual(
            canonical["__intent_patch"]["restart_step_id"],
            "step2",
        )

    def test_build_canonical_user_response_rejects_conflicting_restart_steps(self):
        with self.assertRaisesRegex(run_step.StepError, "restart_step_id.*冲突"):
            run_step.build_canonical_user_response(
                {
                    "intent_patch": {
                        "action": "restart_from_step",
                        "restart_step_id": "step2",
                        "set": {"restart_step_id": "step3"},
                    }
                }
            )

    def test_build_canonical_user_response_allows_action_only_intent_patch(self):
        canonical = run_step.build_canonical_user_response(
            {"intent_patch": {"action": "continue"}}
        )

        self.assertEqual(canonical["action"], "continue")
        self.assertEqual(canonical["__intent_patch"]["set"], {})

    def test_build_canonical_user_response_rejects_unresolved_slots(self):
        with self.assertRaises(run_step.StepError):
            run_step.build_canonical_user_response(
                {
                    "intent_patch": {
                        "action": "continue",
                        "unresolved_slots": ["dependency_source_dirs"],
                    }
                }
            )

    def test_intent_patch_clear_removes_dependency_source_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step2"
            pending = {
                "step_id": "step2",
                "status": "awaiting_user_input",
                "options": [{"id": "continue"}],
            }
            state["step2"]["input"] = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "dependency_source_dirs": [str((project_dir / "dep-repo").resolve())],
                "dependency_repo_mappings": [f"com.example:demo={str((project_dir / 'dep-repo').resolve())}"],
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {
                    "intent_patch": {
                        "action": "continue",
                        "clear": ["dependency_source_dirs"],
                    }
                },
                project_dir,
                target_step_id="step2",
            )

            self.assertNotIn("dependency_source_dirs", updated)
            self.assertNotIn("dependency_repo_mappings", updated)
            self.assertNotIn("dependency_source_dirs", updated_state["step2"]["input"])

    def test_intent_patch_clear_resets_accumulated_manual_coord_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            state = run_step.new_main_state(project_dir / ".upgrade-report")
            pending = {
                "step_id": "step1",
                "status": "awaiting_user_input",
                "kind": "input_request",
            }
            state["step1"]["input"] = {
                "manual_coord_overrides": [
                    "old-lib:1.0 -> com.example:old-lib",
                ],
            }

            state, cleared = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {
                    "intent_patch": {
                        "action": "rerun_current_step",
                        "set": {
                            "manual_coord_overrides": [
                                "discarded-lib:1.0 -> com.example:discarded-lib",
                            ],
                        },
                        "clear": ["manual_coord_overrides"],
                    }
                },
                project_dir,
                target_step_id="step1",
            )

            self.assertNotIn("manual_coord_overrides", cleared)
            self.assertNotIn("manual_coord_overrides", state["step1"]["input"])

            _, resubmitted = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {
                    "action": "rerun_current_step",
                    "manual_coord_overrides": [
                        "new-lib:2.0 -> com.example:new-lib",
                    ],
                },
                project_dir,
                target_step_id="step1",
            )

            self.assertEqual(
                resubmitted["manual_coord_overrides"],
                ["new-lib:2.0 -> com.example:new-lib"],
            )

    def test_apply_user_response_prefers_current_input_over_current_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            fresh_source_dir = project_dir / "module-a" / "src" / "main" / "java"
            fresh_source_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step2"]["output"] = {
                "base_branch": "stale-base",
                "current_branch": "stale-current",
                "source_dirs": ["/tmp/stale-src"],
            }
            state["step2"]["input"] = {
                "base_branch": "fresh-base",
                "current_branch": "fresh-current",
                "source_dirs": [str(fresh_source_dir.resolve())],
            }
            pending = {
                "step_id": "step2",
                "kind": "review",
                "status": "awaiting_user_input",
                "options": [{"id": "continue"}],
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {"action": "continue"},
                project_dir,
                target_step_id="step2",
            )

            self.assertEqual(updated["base_branch"], "fresh-base")
            self.assertEqual(updated["current_branch"], "fresh-current")
            self.assertEqual(updated["source_dirs"], [str(fresh_source_dir.resolve())])
            self.assertEqual(updated_state["step2"]["input"]["base_branch"], "fresh-base")
            self.assertEqual(updated_state["step3"]["input"]["base_branch"], "fresh-base")









    def test_build_resume_command_examples_uses_intent_patch_payload(self):
        examples = run_step.build_resume_command_examples(
            [{"id": "restart_from_step", "label": "从指定步骤重跑"}],
            [],
            {
                "action": {"type": "string"},
                "dependency_source_dirs": {"type": "array"},
                "restart_step_id": {"type": "string"},
                "notes": {"type": "string"},
            },
            Path("/tmp/project"),
            Path("/tmp/project/.upgrade-report"),
        )

        restart_example = examples[0]
        self.assertIn('"intent_patch"', restart_example["command"])
        self.assertIn('"action": "restart_from_step"', restart_example["command"])
        self.assertIn('"restart_step_id": "<step1|step2|step3|step4|step5>"', restart_example["command"])

    def test_resume_command_uses_powershell_safe_argument_quoting(self):
        command = run_step._format_resume_shell_command(
            [
                r"C:\Program Files\Python\python.exe",
                r"C:\work dir\run_step.py",
                "--response-json",
                """{"notes":"O'Brien"}""",
            ],
            platform_name="win32",
        )

        self.assertTrue(command.startswith("& 'C:\\Program Files\\Python\\python.exe'"))
        self.assertIn("'C:\\work dir\\run_step.py'", command)
        self.assertIn("""'{"notes":"O''Brien"}'""", command)

    def test_continue_resume_example_does_not_fill_optional_scope_fields(self):
        examples = run_step.build_resume_command_examples(
            [{"id": "continue", "label": "继续（全量或定向分析）"}],
            [],
            {
                "action": {"type": "string"},
                "dependency_source_dirs": {"type": "array"},
                "selected_targets": {"type": "array"},
                "strict_risk_gate": {"type": "boolean"},
            },
            Path("/tmp/project"),
            Path("/tmp/project/.upgrade-report"),
        )

        command = examples[0]["command"]
        self.assertIn('"action": "continue"', command)
        self.assertNotIn("依赖包完整坐标", command)
        self.assertNotIn("dependency_source_dirs", command)
        self.assertNotIn("strict_risk_gate", command)

    def test_continue_resume_example_fills_every_required_context_field(self):
        examples = run_step.build_resume_command_examples(
            [{"id": "continue", "label": "补齐后继续"}],
            [
                "application_source",
                "base_jdk_home",
                "current_jdk_home",
                "base_tool",
                "current_tool",
                "target_module",
            ],
            {
                "action": {"type": "string"},
                "application_source": {"type": "string"},
                "base_jdk_home": {"type": "string"},
                "current_jdk_home": {"type": "string"},
                "base_tool": {"type": "string", "enum": ["maven", "gradle"]},
                "current_tool": {"type": "string", "enum": ["maven", "gradle"]},
                "target_module": {"type": "string"},
            },
            Path("/tmp/project"),
            Path("/tmp/project/.upgrade-report"),
        )

        command = examples[0]["command"]
        self.assertIn('"application_source": "/abs/path/to/application-repo"', command)
        self.assertIn('"base_jdk_home": "/abs/path/to/jdk-8"', command)
        self.assertIn('"current_jdk_home": "/abs/path/to/jdk-17"', command)
        self.assertIn('"base_tool": "maven"', command)
        self.assertIn('"current_tool": "maven"', command)
        self.assertIn('"target_module": "app-module"', command)

    def test_build_input_normalization_contract_uses_intent_patch_examples(self):
        contract = run_step.build_input_normalization_contract(
            [{"id": "continue", "label": "继续", "description": "继续执行"}],
            ["base_branch"],
            {
                "action": {"type": "string"},
                "base_branch": {"type": "string"},
                "notes": {"type": "string"},
            },
        )

        example = contract["action_examples"][0]["normalized_response_example"]
        self.assertIn("intent_patch", example)
        self.assertEqual(example["intent_patch"]["action"], "continue")
        self.assertEqual(example["intent_patch"]["set"]["base_branch"], "origin/main")

    def test_apply_interaction_protocol_enhancements_defaults_continue_requirements(self):
        interaction = run_step.apply_interaction_protocol_enhancements(
            {
                "step_id": "step1",
                "options": [
                    {"id": "continue", "label": "继续"},
                    {"id": "cancel", "label": "取消"},
                ],
                "required_fields": ["base_branch", "current_branch"],
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "base_branch": {"type": "string"},
                        "current_branch": {"type": "string"},
                    },
                },
                "input_normalization": {"enabled": True},
            },
            "step1",
        )

        self.assertEqual(
            interaction["action_requirements"]["continue"]["required_fields"],
            ["base_branch", "current_branch"],
        )

    def test_selection_protocol_rebuilds_normalization_examples_after_adding_selected_targets(self):
        interaction = run_step.apply_interaction_protocol_enhancements(
            {
                "step_id": "step4",
                "options": [{"id": "continue", "label": "继续"}],
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "step5_selected_coords": {"type": "array"},
                    },
                },
                "required_fields": ["step5_selected_coords"],
                "selection_options": [{"coord": "com.example:demo-lib", "name": "demo-lib"}],
                "input_normalization": run_step.build_input_normalization_contract(
                    [{"id": "continue", "label": "继续"}],
                    [],
                    {
                        "action": {"type": "string"},
                        "step5_selected_coords": {"type": "array"},
                    },
                ),
            },
            "step4",
        )

        normalization = interaction["input_normalization"]
        self.assertEqual(
            interaction["required_fields"],
            ["selected_targets", "scope_mode"],
        )
        self.assertIn("selected_targets", normalization["field_hints"])
        self.assertIn("scope_mode", normalization["field_hints"])
        self.assertIn("selected_targets", interaction["response_schema"]["properties"])
        self.assertIn("scope_mode", interaction["response_schema"]["properties"])
        self.assertNotIn("step5_selected_coords", interaction["response_schema"]["properties"])
        self.assertNotIn("step5_selected_names", interaction["response_schema"]["properties"])
        example = normalization["action_examples"][0]["normalized_response_example"]
        self.assertEqual(
            example["intent_patch"]["set"],
            {
                "selected_targets": ["com.example:demo-lib"],
                "scope_mode": "partial",
            },
        )
        self.assertNotIn("step5_selected_coords", json.dumps(example, ensure_ascii=False))

    def test_validate_pending_interaction_response_enforces_action_requirements(self):
        interaction = {
            "step_id": "step4",
            "response_schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "dependency_source_dirs": {"type": "array"},
                    "dependency_git_ref_overrides": {"type": "array"},
                },
            },
            "action_requirements": {
                "rerun_current_step": {
                    "at_least_one_of": ["dependency_source_dirs", "dependency_git_ref_overrides"],
                }
            },
        }

        with self.assertRaisesRegex(run_step.StepError, "至少需要提供以下字段之一"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "rerun_current_step"},
            )

    def test_validate_pending_interaction_response_allows_name_selected_targets(self):
        selection_options = run_step.build_interaction_selection_options(
            [
                {"coord": "com.example:demo-lib", "name": "demo-lib"},
                {"coord": "org.example:demo-lib", "name": "demo-lib"},
            ]
        )
        interaction = run_step.apply_interaction_protocol_enhancements(
            {
                "step_id": "step4",
                "options": [{"id": "continue", "label": "继续"}],
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                    },
                },
                "selection_options": selection_options,
                "input_normalization": {"enabled": True},
            },
            "step4",
        )

        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "continue",
                "scope_mode": "partial",
                "selected_targets": ["demo-lib"],
            },
        )
        normalized = run_step.resolve_selected_targets(
            interaction.get("selection_resolution") or {},
            ["demo-lib"],
        )

        self.assertEqual(normalized["selected_targets"], ["demo-lib"])
        self.assertEqual(normalized["step5_selected_coords"], [])
        self.assertEqual(normalized["step5_selected_names"], ["demo-lib"])

    def test_step4_scope_confirmation_rejects_notes_only_partial_selection(self):
        selection_options = run_step.build_interaction_selection_options(
            [
                {
                    "coord": "org.apache.seata:seata-common",
                    "name": "seata-common",
                },
                {
                    "coord": "net.sf.json-lib:json-lib:jdk15",
                    "name": "json-lib",
                },
            ]
        )
        # Simulate a persisted checkpoint created before scope_mode was added.
        interaction = {
            "step_id": "step4",
            "options": [{"id": "continue", "label": "继续"}],
            "response_schema": {
                "type": "object",
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "selected_targets": {"type": "array"},
                    "notes": {"type": "string"},
                },
            },
            "selection_resolution": run_step.build_selection_resolution(
                selection_options
            ),
        }

        with self.assertRaisesRegex(run_step.StepError, "必须明确提供 scope_mode"):
            run_step.validate_pending_interaction_response(
                interaction,
                {
                    "action": "continue",
                    "notes": (
                        "只分析 org.apache.seata:seata-common 和 "
                        "net.sf.json-lib:json-lib:jdk15"
                    ),
                },
            )

    def test_step4_scope_confirmation_requires_consistent_explicit_mode(self):
        interaction = run_step.apply_interaction_protocol_enhancements(
            {
                "step_id": "step4",
                "options": [{"id": "continue", "label": "继续"}],
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "notes": {"type": "string"},
                    },
                },
                "selection_options": [
                    {
                        "coord": "org.apache.seata:seata-common",
                        "name": "seata-common",
                    }
                ],
            },
            "step4",
        )

        with self.assertRaisesRegex(run_step.StepError, "scope_mode"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "continue", "notes": "全量分析"},
            )
        with self.assertRaisesRegex(run_step.StepError, "非空 selected_targets"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "continue", "scope_mode": "partial"},
            )
        with self.assertRaisesRegex(run_step.StepError, "不能同时提供 selected_targets"):
            run_step.validate_pending_interaction_response(
                interaction,
                {
                    "action": "continue",
                    "scope_mode": "full",
                    "selected_targets": ["org.apache.seata:seata-common"],
                },
            )
        run_step.validate_pending_interaction_response(
            interaction,
            {"action": "continue", "scope_mode": "full"},
        )

    def test_step5_checkpoint_allows_selected_targets_from_step4_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = self._api_changes_dir(report_dir)
            s4_dir.mkdir(parents=True)
            with (s4_dir / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=run_step.ALL_CHANGED_APIS_FIELDS)
                writer.writeheader()
                writer.writerow({
                    "coord": "com.example:demo-lib",
                    "api_name": "com.example.Demo.removed",
                    "api_simple": "removed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                    "change_type": "REMOVED",
                })
            manifest_steps = {
                "step5": {
                    "title": "调用链分析",
                    "interaction": {
                        "type": "review",
                        "question": "请确认 Step5 结果。",
                        "options": [
                            {"id": "rerun_current_step", "label": "重跑"},
                            {"id": "continue", "label": "继续"},
                        ],
                    },
                    "outputs": ["evidence/call_chain/summary.json"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step5",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        properties = payload["response_schema"]["properties"]
        self.assertIn("selected_targets", properties)
        self.assertNotIn("step5_selected_coords", properties)
        self.assertNotIn("step5_selected_names", properties)
        self.assertTrue(payload["selection_resolution"]["enabled"])
        run_step.validate_pending_interaction_response(
            payload,
            {"action": "rerun_current_step", "selected_targets": ["com.example:demo-lib"]},
        )

    def test_step5_checkpoint_review_files_point_to_alerts_not_summary_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            manifest_steps = {
                "step5": {
                    "title": "调用链分析",
                    "interaction": {
                        "type": "review",
                        "question": "请确认 Step5 结果。",
                        "options": [{"id": "continue", "label": "继续"}],
                    },
                    "outputs": ["evidence/call_chain/summary.json"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step5",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        review_files = "\n".join(payload.get("files_to_review") or [])
        self.assertIn("evidence/call_chain/alerts.csv", review_files)
        self.assertNotIn("summary.txt", review_files)
        self.assertNotIn("summary.json", review_files)

    def test_step5_checkpoint_uses_reader_facing_conclusion_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s5_dir = self._call_chain_dir(report_dir)
            s5_dir.mkdir(parents=True)
            (s5_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "reachable": 1,
                        "user_conclusion_summary": {
                            "probable_impact": 2,
                            "inconclusive": 3,
                        },
                        "quality_gate": {"inconclusive": 3},
                        "uncertain_apis": [
                            {
                                "severity": "P1",
                                "coord": "com.example:demo",
                                "api": "com.example.Demo.changed",
                                "user_conclusion": "当前无法确认",
                                "reason": "字节码命中，但没有找到从当前系统入口到该调用点的完整路径",
                            }
                        ],
                        "not_analyzed_apis": [
                            {
                                "severity": "P1",
                                "coord": "com.example:needs-input",
                                "api": "com.example.Input.changed",
                                "user_conclusion": "需要补充输入",
                                "reason": "缺少依赖源码目录",
                            }
                        ],
                        "not_found_apis": [
                            {
                                "severity": "P2",
                                "coord": "com.example:not-found",
                                "api": "com.example.NotFound.changed",
                                "reason": "静态分析没有发现调用路径",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            manifest_steps = {
                "step5": {
                    "title": "调用链分析",
                    "interaction": {
                        "type": "review",
                        "question": "请确认 Step5 结果。",
                        "options": [{"id": "continue", "label": "继续"}],
                    },
                    "outputs": ["evidence/call_chain/summary.json"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step5",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        checklist_text = "\n".join(payload.get("checklist_lines") or [])
        self.assertIn("仍不确定=3", checklist_text)
        self.assertNotIn("缺少输入=", checklist_text)
        self.assertIn("not_analyzed（输入不足或分析未完成）=1", checklist_text)
        self.assertIn(
            "not_found_in_static_analysis（当前静态范围未找到路径）=1",
            checklist_text,
        )
        self.assertIn("存在候选证据或边界的示例", checklist_text)
        self.assertIn("未完成分析示例", checklist_text)
        self.assertNotIn("当前无法确认=", checklist_text)
        self.assertNotIn("当前无法确认示例", checklist_text)

    def test_build_step_input_context_prefers_current_input_over_previous_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["step1"]["output"] = {
                "source_dirs": ["from-step1"],
                "dependency_source_dirs": [],
            }
            state["step2"]["input"] = {
                "dependency_source_dirs": ["/tmp/dep-repo"],
            }

            context = run_step.build_step_input_context(state, "step2")

            self.assertEqual(context["source_dirs"], ["from-step1"])
            self.assertEqual(context["dependency_source_dirs"], ["/tmp/dep-repo"])

    def test_build_run_context_does_not_guess_workspace_branches(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            args = SimpleNamespace(
                project_dir=str(project_dir),
                report_dir=str(report_dir),
                base_branch=None,
                current_branch=None,
                modules=None,
                source_dirs=None,
                dependency_source_dirs=[],
                dependency_source_mappings=[],
                source_repo_hints=[],
                dependency_repo_mappings=[],
                dependency_git_ref_overrides_json="",
                base_artifact_path="",
                current_artifact_path="",
                base_source_project_dir="",
                current_source_project_dir="",
                base_jdk_home="",
                current_jdk_home="",
                primary_module="",
                manual_coord_overrides=[],
                include_test_scope=False,
                max_depth=None,
                tool="maven",
                strict_risk_gate=False,
            )

            run_context = run_step.build_run_context(args, {}, {})

        self.assertEqual(run_context["base_branch"], "")
        self.assertEqual(run_context["current_branch"], "")

    def test_step0_confirmation_triggers_when_entry_mode_is_still_unknown(self):
        interaction = run_step.build_step0_confirmation_interaction({})

        self.assertIsNotNone(interaction)
        self.assertEqual(interaction["reason_code"], "step0_confirmation_required")
        self.assertEqual(interaction["kind"], "input_request")

    def test_review_interaction_continue_advances_to_next_step(self):
        interaction = {
            "kind": "review",
            "options": [{"id": "continue"}, {"id": "cancel"}],
        }

        self.assertEqual(run_step.current_step_for_pending_interaction("step2", interaction), "step3")

    def test_input_request_interaction_stays_on_current_step(self):
        interaction = {
            "kind": "input_request",
            "options": [{"id": "continue"}, {"id": "cancel"}],
        }

        self.assertEqual(run_step.current_step_for_pending_interaction("step1", interaction), "step1")

    def test_clear_steps_from_preserves_restart_target_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["step2"]["input"] = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "dependency_source_dirs": [],
            }
            state["step4"]["output"] = {"dependency_source_dirs": []}
            pending = {
                "step_id": "step5",
                "status": "awaiting_user_input",
                "options": [{"id": "restart_from_step"}],
            }
            response = {
                "action": "restart_from_step",
                "restart_step_id": "step2",
                "dependency_source_dirs": ["dep-repo"],
            }

            updated_state, _updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                response,
                project_dir,
                target_step_id="step2",
            )
            preserved_input = dict(updated_state["step2"]["input"])
            run_step.clear_steps_from(
                updated_state,
                "step2",
                preserve_current_input=preserved_input,
            )

            self.assertEqual(
                updated_state["step2"]["input"]["dependency_source_dirs"],
                [str((project_dir / "dep-repo").resolve())],
            )
            self.assertEqual(updated_state["step3"]["input"], {})
            self.assertEqual(updated_state["step4"]["output"], {})

    def test_restart_from_step_reuses_pending_step_branch_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["step2"]["input"] = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
            }
            state["step4"]["output"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "dependency_repo_mappings": [f"com.example:demo={str((project_dir / 'dep-repo').resolve())}"],
            }
            pending = {
                "step_id": "step4",
                "status": "awaiting_user_input",
                "options": [{"id": "restart_from_step"}],
            }
            response = {
                "action": "restart_from_step",
                "restart_step_id": "step2",
                "notes": "从 step2 重新开始",
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                response,
                project_dir,
                target_step_id="step2",
            )

            self.assertEqual(updated["base_branch"], "base")
            self.assertEqual(updated["current_branch"], "current")
            self.assertEqual(updated_state["step2"]["input"]["base_branch"], "base")
            self.assertEqual(updated_state["step2"]["input"]["current_branch"], "current")

    def test_restart_from_step_prefers_pending_checkpoint_context_over_stale_target_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            fresh_dep_repo = project_dir / "dep-repo-new"
            fresh_dep_repo.mkdir()
            state = run_step.new_main_state(report_dir)
            state["step2"]["input"] = {
                "base_branch": "stale-base",
                "current_branch": "stale-current",
                "dependency_source_dirs": [str((project_dir / "dep-repo-old").resolve())],
            }
            state["step4"]["output"] = {
                "base_branch": "fresh-base",
                "current_branch": "fresh-current",
                "dependency_source_dirs": [str(fresh_dep_repo.resolve())],
            }
            pending = {
                "step_id": "step4",
                "kind": "review",
                "status": "awaiting_user_input",
                "options": [{"id": "restart_from_step"}],
            }

            updated_state, updated = run_step.apply_user_response_to_main_state(
                state,
                pending,
                {
                    "action": "restart_from_step",
                    "restart_step_id": "step2",
                },
                project_dir,
                target_step_id="step2",
            )

            self.assertEqual(updated["base_branch"], "fresh-base")
            self.assertEqual(updated["current_branch"], "fresh-current")
            self.assertEqual(
                updated["dependency_source_dirs"],
                [str(fresh_dep_repo.resolve())],
            )
            self.assertEqual(updated_state["step2"]["input"]["base_branch"], "fresh-base")
            self.assertEqual(updated_state["step2"]["input"]["current_branch"], "fresh-current")

    def test_non_pending_restart_reuses_latest_step_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            state["state"].update({
                "current_step": "step5",
                "completed_step": "step4",
                "status": "completed",
            })
            state["step2"]["input"] = {"source_dirs": [str(project_dir / "src/main/java")]}
            state["step5"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str(project_dir / "src/main/java")],
            }
            args = SimpleNamespace(step="auto")
            stderr = io.StringIO()

            with patch.object(sys, "stderr", stderr):
                result = run_step.apply_non_pending_structured_response(
                    args,
                    project_dir,
                    report_dir,
                    state,
                    {
                        "action": "restart_from_step",
                        "restart_step_id": "step2",
                    },
                )

            self.assertEqual(result["step_id"], "step2")
            self.assertEqual(result["main_state"]["step2"]["input"]["base_branch"], "base")
            self.assertEqual(result["main_state"]["step2"]["input"]["current_branch"], "current")
            self.assertIn("分析对象与依赖范围及之前的正式产物继续保留", stderr.getvalue())
            self.assertIn("升级上下文及之后的产物会按新输入重建", stderr.getvalue())

    def test_blocked_system_state_allows_action_only_rerun(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            retained_path = (
                run_step.evidence_static_scan_dir(report_dir)
                / "s3_jdk_removed_api.csv"
            )
            incomplete_path = (
                run_step.step4_api_changes_dir(report_dir)
                / "partial.csv"
            )
            self._write_text(retained_path, "retained\n")
            self._write_text(incomplete_path, "incomplete\n")
            state = run_step.new_main_state(report_dir)
            state["state"].update({
                "current_step": "step4",
                "completed_step": "step3",
                "status": "blocked_by_system",
                "blocking_reason": "temporary Python failure",
            })
            state["step3"]["output"] = {"completed": True}
            state["step4"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
            }
            state["step4"]["output"] = {"partial": True}

            with patch.object(sys, "stderr", io.StringIO()):
                result = run_step.apply_non_pending_structured_response(
                    SimpleNamespace(step="auto"),
                    project_dir,
                    report_dir,
                    state,
                    {"action": "rerun_current_step"},
                )

            self.assertEqual(result["step_id"], "step4")
            self.assertEqual(state["state"]["status"], "ready")
            self.assertIsNone(state["state"]["blocking_reason"])
            self.assertEqual(state["step3"]["output"], {"completed": True})
            self.assertEqual(state["step4"]["input"]["base_branch"], "base")
            self.assertEqual(state["step4"]["output"], {})
            self.assertTrue(retained_path.exists())
            self.assertTrue(incomplete_path.exists())

    def test_execute_step1_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "step0_confirmed": True,
                "base_branch": "main",
                "current_branch": "feature/demo",
                "primary_module": "app",
                "modules": ["app"],
                "manual_coord_overrides": ["demo:1.0.0 -> com.example:demo"],
            }
            manifest_steps = {"step1": {"gate": "step1_scope"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "validate_step1_runtime_inputs", return_value={"status": "passed"}), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                 patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step1", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s1_dep_diff.py")
        self.assertNotIn("--base", captured["script_args"])
        self.assertNotIn("--current", captured["script_args"])
        self.assertNotIn("--primary-module", captured["script_args"])
        self.assertNotIn("--modules", captured["script_args"])
        self.assertNotIn("--manual-coord-override", captured["script_args"])

    def test_execute_step1_accepts_gradle_run_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            (project_dir / "settings.gradle").write_text("include ':app'\n", encoding="utf-8")
            (project_dir / "build.gradle").write_text("group = 'com.acme'\n", encoding="utf-8")
            (project_dir / "app").mkdir()
            (project_dir / "app/build.gradle").write_text("plugins { id 'java' }\n", encoding="utf-8")
            (project_dir / "app/src/main/java").mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "step0_confirmed": True,
                "tool": "gradle",
                "base_branch": "main",
                "current_branch": "feature/demo",
                "target_module": ":app",
            }
            captured = []
            with patch.object(run_step, "run_python", side_effect=lambda name, *_args, **_kwargs: captured.append(name)), \
                    patch.object(run_step, "validate_step1_runtime_inputs", return_value={"status": "passed"}), \
                    patch.object(run_step, "ensure_exists"), \
                    patch.object(run_step, "run_gate"), \
                    patch.object(run_step, "build_interaction_payload", return_value={}):
                run_step.execute_step(
                    "step1",
                    args,
                    {"step1": {"gate": "step1_scope"}},
                    run_context,
                )

        self.assertEqual(captured, ["s1_dep_diff.py"])

    def test_execute_step2_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "base_branch": "main",
                "current_branch": "feature/demo",
                "base_resolved_commit": "a" * 40,
                "current_resolved_commit": "b" * 40,
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "provided",
            }
            manifest_steps = {"step2": {"gate": "context"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                 patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step2", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s2_context_from_deps.py")
        self.assertNotIn("--base", captured["script_args"])
        self.assertNotIn("--current", captured["script_args"])
        self.assertNotIn("--source-dirs", captured["script_args"])

    def test_execute_step2_missing_branches_error_points_to_main_state_and_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "base_branch": "",
                "current_branch": "",
                "artifact_input_mode": False,
            }
            manifest_steps = {"step2": {"gate": "context"}}

            with patch.object(run_step, "ensure_exists"):
                with self.assertRaisesRegex(
                    run_step.StepError,
                    "main_state.json.*step2.input / step1.output.*--response-json / --response-file",
                ):
                    run_step.execute_step("step2", args, manifest_steps, run_context)

    def test_execute_step2_same_branch_error_no_longer_points_to_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "base_branch": "main",
                "current_branch": "main",
                "base_resolved_commit": "a" * 40,
                "current_resolved_commit": "a" * 40,
                "artifact_input_mode": False,
            }
            manifest_steps = {"step2": {"gate": "context"}}

            with patch.object(run_step, "ensure_exists"):
                with self.assertRaisesRegex(
                    run_step.StepError,
                    r"修正远端 ref.*不同 commit",
                ):
                    run_step.execute_step("step2", args, manifest_steps, run_context)

    def test_execute_step2_rejects_movable_refs_without_pinned_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "base_branch": "release-old",
                "current_branch": "release-new",
                "artifact_input_mode": False,
            }

            with patch.object(run_step, "ensure_exists"):
                with self.assertRaises(run_step.StepError) as raised:
                    run_step.execute_step(
                        "step2",
                        args,
                        {"step2": {"gate": "context"}},
                        run_context,
                    )

        self.assertEqual(
            raised.exception.reason_codes,
            ["STEP2_SOURCE_COMMIT_NOT_PINNED"],
        )

    def test_refresh_step2_outputs_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            self._write_text(run_step.step1_dep_changes_path(report_dir), "coord\n", encoding="utf-8")
            run_context = {
                "base_branch": "main",
                "current_branch": "feature/demo",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
            }
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "run_python", side_effect=fake_run_python):
                run_step.refresh_step2_outputs(report_dir, project_dir, run_context)

        self.assertEqual(captured["script_name"], "s2_context_from_deps.py")
        self.assertNotIn("--base", captured["script_args"])
        self.assertNotIn("--current", captured["script_args"])
        self.assertNotIn("--source-dirs", captured["script_args"])

    def test_execute_step3_passes_only_business_scan_roots_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            self._write_text(run_step.step2_context_path(report_dir), "{}", encoding="utf-8")
            self._write_text(run_step.step1_current_resolved_path(report_dir), "coord\n", encoding="utf-8")
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "step0_confirmed": True,
                "analysis_mode": "checkout_build",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "provided",
                "include_test_scope": True,
            }
            manifest_steps = {"step3": {"gate": "scan"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                 patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step3", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s3_scan.py")
        source_index = captured["script_args"].index("--source-dirs")
        self.assertEqual(
            captured["script_args"][source_index + 1:],
            [str((project_dir / "src/main/java").resolve())],
        )
        self.assertNotIn("--include-test-scope", captured["script_args"])
        self.assertNotIn("--jdk-upgraded", captured["script_args"])
        self.assertNotIn("--sb-major-upgrade", captured["script_args"])
        self.assertNotIn("--target-jdk", captured["script_args"])
        self.assertNotIn("--no-source", captured["script_args"])

    def test_execute_step3_continue_without_more_source_keeps_build_source_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            self._write_text(run_step.step2_context_path(report_dir), "{}", encoding="utf-8")
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "step0_confirmed": True,
                "analysis_mode": "checkout_build",
                "base_branch": "main",
                "current_branch": "upgrade",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "auto_detected",
            }
            manifest_steps = {"step3": {"gate": "scan"}}
            captured = {}

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured["script_name"] = script_name
                captured["script_args"] = list(script_args)

            with patch.object(run_step, "ensure_exists"), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(run_step, "run_gate"):
                run_step.execute_step("step3", args, manifest_steps, run_context)

        self.assertEqual(captured["script_name"], "s3_scan.py")
        self.assertNotIn("--no-source", captured["script_args"])
        source_index = captured["script_args"].index("--source-dirs")
        self.assertEqual(
            captured["script_args"][source_index + 1:],
            [str((project_dir / "src/main/java").resolve())],
        )

    def test_execute_step4_does_not_pass_business_inputs_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            (project_dir / "src" / "main" / "java").mkdir(parents=True)
            dep_repo = project_dir / "demo-lib-repo"
            (dep_repo / "src" / "main" / "java").mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>demo-lib</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )
            self._write_text(run_step.step1_dep_changes_path(report_dir),
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            self._write_text(run_step.step2_context_path(report_dir),
                "{\"changed_dependencies\":[{\"coord\":\"com.example:demo-lib\"}]}",
                encoding="utf-8",
            )
            args = self._make_default_args(project_dir, report_dir)
            run_context = run_step.build_run_context(
                args,
                {},
                {"dependency_repo_mappings": [str(dep_repo)]},
            )
            config = project_dir / "binary.json"
            config.write_text("{}", encoding="utf-8")
            run_context["binary_pipeline_config"] = str(config)
            manifest_steps = {"step4": {"gate": "binary_diff"}}
            captured = []

            def fake_run_python(script_name, script_args, _cwd, **_kwargs):
                captured.append((script_name, list(script_args)))
                self.assertEqual(script_name, "binary_pipeline.py")
                self._write_fake_step4_pipeline_result(script_args)

            def prepare_report(**kwargs):
                return self._fake_step4_report_result(kwargs["report_dir"])

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "ensure_exists"), \
                 patch.object(
                     run_step,
                     "materialize_pinned_source_workspace",
                     return_value=nullcontext({
                         "source_dirs": list(run_context.get("source_dirs") or []),
                         "project_root": project_dir,
                     }),
                 ), \
                 patch.object(
                     run_step,
                     "materialize_pinned_dependency_source_workspaces",
                     side_effect=lambda context, _report: nullcontext(context),
                 ), \
                 patch.object(run_step, "run_python", side_effect=fake_run_python), \
                 patch.object(
                     run_step,
                     "_prepare_binary_report_publication_candidate_in_process",
                     side_effect=prepare_report,
                 ), \
                 patch.object(
                     run_step,
                     "_complete_binary_step4_after_gate",
                     return_value=True,
                 ), \
                 patch.object(run_step, "build_interaction_payload", return_value={}):
                run_step.execute_step("step4", args, manifest_steps, run_context)

        self.assertEqual([item[0] for item in captured], ["binary_pipeline.py"])
        pipeline_args = captured[0][1]
        self.assertNotIn("--dependency-repo-mappings", pipeline_args)
        self.assertNotIn("--source-branches", pipeline_args)
        self.assertNotIn("--allow-degraded", pipeline_args)


    def test_run_python_has_no_default_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            captured = {}

            def fake_run_cmd(cmd, cwd=None, timeout=None, _input_text=None, env=None):
                captured["cmd"] = list(cmd)
                captured["cwd"] = cwd
                captured["timeout"] = timeout
                captured["env"] = dict(env or {})
                return "", "", 0

            with patch.object(run_step, "run_cmd", side_effect=fake_run_cmd):
                run_step.run_python("s3_scan.py", ["--all"], tmp, report_dir=tmp)

        self.assertIsNone(captured["timeout"])
        self.assertEqual(captured["cwd"], tmp)

    def test_run_python_streams_binary_pipeline_progress_from_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            captured = {}

            def fake_run_cmd(_cmd, **kwargs):
                captured.update(kwargs)
                return "", "oracle progress\n", 0

            with patch.object(
                run_step, "run_cmd", side_effect=fake_run_cmd
            ), patch.object(run_step, "print_output") as print_mock:
                run_step.run_python(
                    "binary_pipeline.py", [], tmp, report_dir=tmp
                )

        self.assertTrue(captured["stream_output"])
        self.assertFalse(captured["stream_stdout"])
        print_mock.assert_called_once_with("", "")

    def test_run_python_preserves_structured_pipeline_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_path = root / "pipeline-result.json"

            def fail(_cmd, **_kwargs):
                result_path.write_text(json.dumps({
                    "schema": (
                        "java-upgrade-analyzer.binary-pipeline-failure.v1"
                    ),
                    "status": "failed",
                    "reason_code": "BINARY_JDK_PREFLIGHT_FAILED",
                    "failure_type": "BinaryPipelineError",
                    "detail": "preflight failed",
                    "cause": None,
                    "failed_phase": "static_preflight",
                    "last_progress": {
                        "attempt_identity": "a" * 64,
                        "current_phase": "static_preflight",
                    },
                    "attempt_identity": "a" * 64,
                    "progress_bound_to_attempt": True,
                    "core_transaction_status": "failed",
                    "core_transaction_succeeded": False,
                    "core_result_receipt": None,
                    "traceback": "preflight traceback",
                    "fail_closed": True,
                }), encoding="utf-8")
                return "", "pipeline failed", 1

            with patch.object(run_step, "run_cmd", side_effect=fail):
                with self.assertRaises(run_step.StepError) as raised:
                    run_step.run_python(
                        "binary_pipeline.py",
                        ["--result-json", str(result_path)],
                        root,
                        report_dir=root,
                    )

        self.assertIn(
            "BINARY_JDK_PREFLIGHT_FAILED", raised.exception.reason_codes
        )
        self.assertEqual(
            raised.exception.diagnostic["structured_result"]["failed_phase"],
            "static_preflight",
        )

    def test_run_python_recovers_exact_pipeline_failure_from_final_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_path = root / "missing-pipeline-result.json"
            receipt = {
                "result_generation_identity": "b" * 64,
                "activation_identity": "c" * 64,
                "activation_disposition": (
                    "private_candidate_pending_parent_commit"
                ),
            }
            public_failure = {
                "schema": (
                    "java-upgrade-analyzer.binary-pipeline-failure.v1"
                ),
                "status": "failed",
                "reason_code": "BINARY_PIPELINE_RESULT_PERSIST_FAILED",
                "failure_type": "OSError",
                "detail": "result sink unavailable",
                "cause": {
                    "failure_stage": "result_persistence",
                    "failure_type": "OSError",
                },
                "failed_phase": "result_delivery",
                "last_progress": {},
                "attempt_identity": "a" * 64,
                "progress_bound_to_attempt": False,
                "core_transaction_status": "succeeded",
                "core_transaction_succeeded": True,
                "core_result_receipt": receipt,
                "fail_closed": True,
            }
            stderr = "\n".join((
                json.dumps({
                    "level": "error",
                    "reason_code": "MUST_NOT_BE_PARSED",
                }),
                json.dumps(public_failure),
            )) + "\n"

            def fail_with_invalid_result(_cmd, **_kwargs):
                result_path.write_text("{invalid-json", encoding="utf-8")
                return "", stderr, 1

            with patch.object(
                run_step, "run_cmd", side_effect=fail_with_invalid_result
            ), patch.object(run_step, "print_output"):
                with self.assertRaises(run_step.StepError) as caught:
                    run_step.run_python(
                        "binary_pipeline.py",
                        ["--result-json", str(result_path)],
                        root,
                        report_dir=root,
                    )

        self.assertIn(
            "BINARY_PIPELINE_RESULT_PERSIST_FAILED",
            caught.exception.reason_codes,
        )
        structured = caught.exception.diagnostic["structured_result"]
        self.assertEqual(structured["core_transaction_status"], "succeeded")
        self.assertEqual(structured["core_result_receipt"], receipt)

    def test_run_python_does_not_treat_arbitrary_stderr_json_as_pipeline_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_path = root / "missing-pipeline-result.json"
            arbitrary_log = json.dumps({
                "status": "failed",
                "reason_code": "MUST_NOT_BE_PARSED",
                "failed_phase": "validated_generation_activation",
            }) + "\n"
            with patch.object(
                run_step,
                "run_cmd",
                return_value=("", arbitrary_log, 1),
            ), patch.object(run_step, "print_output"):
                with self.assertRaises(run_step.StepError) as caught:
                    run_step.run_python(
                        "binary_pipeline.py",
                        ["--result-json", str(result_path)],
                        root,
                        report_dir=root,
                    )

        self.assertNotIn("MUST_NOT_BE_PARSED", caught.exception.reason_codes)
        self.assertEqual(
            caught.exception.diagnostic["structured_result"], {}
        )

    def test_step6_failure_owner_requires_complete_child_contract(self):
        valid = run_step.StepError(
            "Step6 failed",
            reason_codes=["BINARY_STEP6_INTERNAL_INPUT_INVALID"],
            diagnostic={"structured_result": {
                "schema": (
                    "java-upgrade-analyzer."
                    "binary-report-publication-failure.v1"
                ),
                "status": "failed",
                "phase": "step6",
                "reason_code": "BINARY_STEP6_INTERNAL_INPUT_INVALID",
                "owner_step": "step2",
                "failure_contract": {
                    "schema": (
                        "java-upgrade-analyzer."
                        "step6-internal-input-failure.v1"
                    ),
                    "status": "failed",
                    "owner_step": "step2",
                    "failures": [{"owner_step": "step2"}],
                },
            }},
        )
        forged = run_step.StepError(
            "Step6 failed",
            diagnostic={"structured_result": {
                "schema": (
                    "java-upgrade-analyzer."
                    "binary-report-publication-failure.v1"
                ),
                "status": "failed",
                "phase": "step6",
                "reason_code": "BINARY_STEP6_INTERNAL_INPUT_INVALID",
                "owner_step": "step1",
                "failure_contract": {
                    "schema": (
                        "java-upgrade-analyzer."
                        "step6-internal-input-failure.v1"
                    ),
                    "status": "failed",
                    "owner_step": "step3",
                },
            }},
        )

        self.assertEqual(
            run_step.step6_internal_input_failure_owner_from_step_error(
                valid
            ),
            "step2",
        )
        self.assertIsNone(
            run_step.step6_internal_input_failure_owner_from_step_error(
                forged
            )
        )

    def test_final_report_gate_preserves_step6_owner_contract(self):
        structured_result = {
            "schema": (
                "java-upgrade-analyzer."
                "binary-report-publication-failure.v1"
            ),
            "status": "failed",
            "phase": "step6",
            "reason_code": "BINARY_STEP6_INTERNAL_INPUT_INVALID",
            "owner_step": "step2",
            "failure_contract": {
                "schema": (
                    "java-upgrade-analyzer."
                    "step6-internal-input-failure.v1"
                ),
                "status": "failed",
                "owner_step": "step2",
                "failures": [{"owner_step": "step2"}],
            },
        }
        child_error = run_step.StepError(
            "gate failed",
            reason_codes=["BINARY_STEP6_INTERNAL_INPUT_INVALID"],
            diagnostic={"structured_result": structured_result},
        )
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            run_step, "run_python", side_effect=child_error
        ) as run_python:
            with self.assertRaises(run_step.StepError) as caught:
                run_step.run_gate(
                    "binary_final_report",
                    Path(tmp) / ".upgrade-report",
                    Path(tmp),
                )

        gate_args = run_python.call_args.args[1]
        self.assertIn("--result-json", gate_args)
        self.assertEqual(
            run_step.step6_internal_input_failure_owner_from_step_error(
                caught.exception
            ),
            "step2",
        )

    def test_step6_internal_input_failure_rebuilds_from_earliest_owner(self):
        for owner_step in ("step1", "step2", "step3"):
            with self.subTest(owner_step=owner_step), tempfile.TemporaryDirectory() as tmp:
                project_dir = Path(tmp) / "project"
                source_dir = project_dir / "src/main/java"
                source_dir.mkdir(parents=True)
                report_dir = project_dir / ".upgrade-report"
                state = run_step.new_main_state(report_dir)
                state["state"].update({
                    "current_step": "step6",
                    "completed_step": "step5",
                    "status": "ready",
                })
                state["step6"]["input"] = {
                    "target_module": ".",
                    "source_dirs": [str(source_dir)],
                    "source_dirs_status": "explicit",
                }
                run_step.save_main_state(report_dir, state)
                executed = []

                def fake_execute(step_id, *_args, **_kwargs):
                    executed.append(step_id)
                    if step_id != "step6":
                        return None
                    raise run_step.StepError(
                        "binary_report.py execution failed",
                        reason_codes=[
                            "BINARY_STEP6_INTERNAL_INPUT_INVALID"
                        ],
                        diagnostic={"structured_result": {
                            "schema": (
                                "java-upgrade-analyzer."
                                "binary-report-publication-failure.v1"
                            ),
                            "status": "failed",
                            "phase": "step6",
                            "reason_code": (
                                "BINARY_STEP6_INTERNAL_INPUT_INVALID"
                            ),
                            "owner_step": owner_step,
                            "failure_contract": {
                                "schema": (
                                    "java-upgrade-analyzer."
                                    "step6-internal-input-failure.v1"
                                ),
                                "status": "failed",
                                "owner_step": owner_step,
                                "failures": [{
                                    "owner_step": owner_step,
                                }],
                            },
                        }},
                    )

                steps = {
                    step: {"gate": "noop", "interaction": None}
                    for step in run_step.STEP_SEQUENCE
                }
                with patch.object(
                    run_step,
                    "contract_payload",
                    return_value={"status": "passed", "checks": []},
                ), patch.object(
                    run_step,
                    "load_manifest",
                    return_value=({"auto_run_until_checkpoint": False}, steps),
                ), patch.object(
                    run_step,
                    "detect_integrity_repair_step",
                    return_value=None,
                ), patch.object(
                    run_step, "detect_build_tool", return_value="maven"
                ), patch.object(
                    run_step, "execute_step", side_effect=fake_execute
                ), patch.object(
                    run_step,
                    "_recover_and_apply_step4_startup_state",
                    return_value={
                        "action": run_step._STEP4_RELEASE_CURRENT,
                        "applied": False,
                        "forced_step_id": "",
                        "discard_structured_response": False,
                    },
                ), patch.object(
                    run_step,
                    "_apply_downstream_release_startup_state",
                    return_value={
                        "forced_step_id": "",
                        "discard_structured_response": False,
                        "release": {},
                    },
                ):
                    exit_code = run_step.main(
                        [
                            "--step", "step6",
                            "--project-dir", str(project_dir),
                            "--report-dir", str(report_dir),
                        ],
                        _skip_environment_contract=True,
                    )

                self.assertEqual(exit_code, 0)
                self.assertEqual(executed, ["step6", owner_step])
                saved = run_step.load_main_state(report_dir)
                self.assertEqual(
                    saved["state"]["completed_step"], owner_step
                )
                self.assertFalse(
                    run_step._STEP6_INTERNAL_INPUT_RECOVERY_ATTEMPTS
                )

    def test_run_python_emits_heartbeat_during_silent_long_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            stderr = io.StringIO()

            def slow_run_cmd(*_args, **_kwargs):
                time.sleep(0.06)
                return "", "", 0

            with patch.dict(
                os.environ,
                {"JUA_HEARTBEAT_INTERVAL_SECONDS": "0.01"},
            ), patch.object(
                run_step,
                "run_cmd",
                side_effect=slow_run_cmd,
            ), patch.object(sys, "stderr", stderr):
                run_step.run_python(
                    "s3_scan.py",
                    ["--all"],
                    tmp,
                    report_dir=report_dir,
                )

            progress_path = report_dir / ".runtime" / "observability" / "progress.jsonl"
            events = [
                json.loads(line)
                for line in progress_path.read_text(encoding="utf-8").splitlines()
            ]

        self.assertIn("[进度][兼容性线索][运行中]", stderr.getvalue())
        self.assertTrue(any(item.get("phase") == "heartbeat" for item in events))



    def test_keyboard_interrupt_cleans_partial_current_step_and_can_resume_safely(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"].update(
                {
                    "current_step": "step3",
                    "completed_step": "step2",
                    "status": "ready",
                }
            )
            state["step3"]["input"] = {"source_dirs": [str(project_dir)]}
            run_step.save_main_state(report_dir, state)
            partial_output = (
                report_dir / "evidence" / "static_scan" / "s3_jdk_removed_api.csv"
            )
            partial_output.parent.mkdir(parents=True)
            partial_output.write_text("partial\n", encoding="utf-8")
            stderr = io.StringIO()

            with patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step3": {"gate": "scan", "interaction": None}}),
            ), patch.object(
                run_step,
                "detect_integrity_repair_step",
                return_value="",
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=KeyboardInterrupt,
            ), patch.object(sys, "stderr", stderr):
                exit_code = run_step.main(
                    [
                        "--step", "auto",
                        "--project-dir", str(project_dir),
                        "--report-dir", str(report_dir),
                    ],
                    _skip_environment_contract=True,
                )

            saved = run_step.load_main_state(report_dir)
            landing = (report_dir / "README.md").read_text(encoding="utf-8")
            partial_exists_after = partial_output.exists()

        self.assertEqual(exit_code, run_step.EXIT_INTERRUPTED)
        self.assertEqual(saved["state"]["status"], "paused_by_user")
        self.assertEqual(saved["state"]["current_step"], "step3")
        self.assertEqual(saved["state"]["completed_step"], "step2")
        self.assertFalse(partial_exists_after)
        self.assertIn("已安全停止当前任务", stderr.getvalue())
        self.assertIn("从兼容性线索重新开始", stderr.getvalue())
        self.assertIn("从当前任务安全重试", landing)

    def test_completed_integrity_check_repairs_from_earliest_missing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            for relative_path in (
                "evidence/context/context.json",
                "evidence/api_changes/all_changed_apis.csv",
                "evidence/call_chain/summary.json",
            ):
                path = report_dir / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")

            repair_step = run_step.detect_integrity_repair_step("step6", report_dir)

        self.assertEqual(repair_step, "step1")

    def test_cli_main_hides_unexpected_traceback_and_records_internal_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            stderr = io.StringIO()

            with patch.object(
                run_step,
                "main",
                side_effect=RuntimeError("internal detail must stay private"),
            ), patch.object(sys, "stderr", stderr):
                exit_code = run_step.cli_main(["--report-dir", str(report_dir)])

            diagnostic_path = (
                report_dir / ".runtime" / "observability" / "internal_error.json"
            )
            diagnostic = json.loads(diagnostic_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 1)
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertNotIn("internal detail must stay private", stderr.getvalue())
        self.assertIn("已停止以避免生成不完整结论", stderr.getvalue())
        self.assertEqual(diagnostic["error_type"], "RuntimeError")
        self.assertIn("internal detail must stay private", diagnostic["traceback"])

    def test_handle_step4_resume_followups_seeds_step5_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step4"]["input"] = {
                "step5_selected_coords": ["com.example:demo"],
                "step5_selected_names": ["core-lib"],
            }
            state["step5"]["input"] = {"source_dirs": ["/tmp/src"]}

            run_step.handle_step4_resume_followups(
                state,
                report_dir,
                "step4",
                "continue",
            )

            self.assertEqual(state["step5"]["input"]["step5_selected_coords"], ["com.example:demo"])
            self.assertEqual(state["step5"]["input"]["step5_selected_names"], ["core-lib"])

    def test_handle_step4_resume_followups_clears_stale_step5_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step4"]["input"] = {}
            state["step5"]["input"] = {
                "step5_selected_coords": ["com.example:stale"],
                "step5_selected_names": ["stale-lib"],
            }

            run_step.handle_step4_resume_followups(
                state,
                report_dir,
                "step4",
                "continue",
            )

            self.assertNotIn("step5_selected_coords", state["step5"]["input"])
            self.assertNotIn("step5_selected_names", state["step5"]["input"])

    def test_full_continue_clears_previous_step4_and_step5_target_selection(self):
        for response_set in (
            {"scope_mode": "full"},
            {"scope_mode": "full", "selected_targets": []},
        ):
            with self.subTest(response_set=response_set), tempfile.TemporaryDirectory() as tmp:
                project_dir = Path(tmp)
                report_dir = project_dir / ".upgrade-report"
                report_dir.mkdir(parents=True)
                state = run_step.new_main_state(report_dir)
                state["step4"]["input"] = {
                    "step5_selected_coords": ["com.example:previous"],
                    "step5_selected_names": ["previous"],
                }
                state["step5"]["input"] = {
                    "step5_selected_coords": ["com.example:previous"],
                    "step5_selected_names": ["previous"],
                }
                pending_interaction = run_step.apply_interaction_protocol_enhancements(
                    {
                        "step_id": "step4",
                        "kind": "review",
                        "options": [{"id": "continue", "label": "继续"}],
                        "response_schema": {
                            "type": "object",
                            "required": ["action"],
                            "properties": {"action": {"type": "string"}},
                        },
                        "selection_options": [{"coord": "com.example:previous", "name": "previous"}],
                    },
                    "step4",
                    project_dir=project_dir,
                    report_dir=report_dir,
                )

                updated_state, _ = run_step.apply_user_response_to_main_state(
                    state,
                    pending_interaction,
                    {"intent_patch": {"action": "continue", "set": response_set}},
                    project_dir,
                    target_step_id="step4",
                )
                run_step.handle_step4_resume_followups(
                    updated_state,
                    report_dir,
                    "step4",
                    "continue",
                )

                self.assertNotIn("step5_selected_coords", updated_state["step4"]["input"])
                self.assertNotIn("step5_selected_names", updated_state["step4"]["input"])
                self.assertNotIn("step5_selected_coords", updated_state["step5"]["input"])
                self.assertNotIn("step5_selected_names", updated_state["step5"]["input"])

    def test_new_target_selection_replaces_old_coordinate_and_name_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step4"]["input"] = {
                "step5_selected_coords": ["com.old:old-lib"],
                "step5_selected_names": ["old-lib"],
            }
            pending_interaction = run_step.apply_interaction_protocol_enhancements(
                {
                    "step_id": "step4",
                    "kind": "review",
                    "options": [{"id": "continue", "label": "继续"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["action"],
                        "properties": {"action": {"type": "string"}},
                    },
                    "selection_options": [{"coord": "com.new:new-lib", "name": "new-lib"}],
                },
                "step4",
            )

            updated_state, _ = run_step.apply_user_response_to_main_state(
                state,
                pending_interaction,
                {
                    "intent_patch": {
                        "action": "continue",
                        "set": {"selected_targets": ["com.new:new-lib"]},
                    }
                },
                project_dir,
                target_step_id="step4",
            )

        self.assertEqual(
            updated_state["step4"]["input"]["step5_selected_coords"],
            ["com.new:new-lib"],
        )
        self.assertNotIn("step5_selected_names", updated_state["step4"]["input"])

    def test_full_continue_with_no_current_candidates_clears_old_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["step4"]["input"] = {
                "step5_selected_coords": ["com.old:old-lib"],
                "step5_selected_names": ["old-lib"],
            }
            pending_interaction = {
                "step_id": "step4",
                "kind": "review",
                "selection_resolution": {},
            }

            updated_state, _ = run_step.apply_user_response_to_main_state(
                state,
                pending_interaction,
                {"intent_patch": {"action": "continue", "set": {}}},
                project_dir,
                target_step_id="step4",
            )

        self.assertNotIn("step5_selected_coords", updated_state["step4"]["input"])
        self.assertNotIn("step5_selected_names", updated_state["step4"]["input"])

    def test_fallback_high_risk_count_matches_step4_when_severity_is_present(self):
        summary = run_step.build_step5_selection_summary(
            [
                {
                    "coord": "com.example:demo",
                    "severity": "P2",
                    "change_type": "REMOVED",
                }
            ]
        )

        target = summary["available_targets"][0]
        self.assertEqual(target["high_risk_api_count"], 0)
        self.assertTrue(target["recommended"])

    def test_build_interaction_payload_step4_exposes_step5_target_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = self._api_changes_dir(report_dir)
            s4_dir.mkdir(parents=True)
            with open(s4_dir / "all_changed_apis.csv", "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=run_step.ALL_CHANGED_APIS_FIELDS)
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "com.example:demo-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Demo.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "classfile_contract",
                    }
                )
            manifest_steps = {
                "step4": {
                    "title": "jar 包变更对比",
                    "interaction": {
                        "type": "review",
                        "question": "请确认",
                        "options": [{"id": "continue", "label": "继续", "description": "继续"}],
                    },
                    "outputs": ["evidence/api_changes/all_changed_apis.csv"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step4",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

            properties = payload["response_schema"]["properties"]
            self.assertIn("selected_targets", properties)
            self.assertIn("scope_mode", properties)
            self.assertNotIn("step5_selected_coords", properties)
            self.assertNotIn("step5_selected_names", properties)
            self.assertIn("scope_mode", payload["required_fields"])
            self.assertIn(
                "scope_mode",
                payload["action_requirements"]["continue"]["required_fields"],
            )
            self.assertTrue(payload["selection_resolution"]["enabled"])
            self.assertEqual(payload["selection_options"][0]["coord"], "com.example:demo-lib")
            self.assertEqual(payload["selection_options"][0]["name"], "demo-lib")
            self.assertEqual(payload["selection_options"][0]["selection_key"], "coord:com.example:demo-lib")
            self.assertEqual(payload["recommended_candidate_count"], 1)
            self.assertEqual(
                payload["recommended_selection_options"][0]["coord"],
                "com.example:demo-lib",
            )
            self.assertNotIn(
                "scope_mode",
                "\n".join(payload["user_decision_card"]),
            )

    def test_apply_user_response_to_main_state_resolves_selected_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            pending_interaction = run_step.apply_interaction_protocol_enhancements(
                {
                    "step_id": "step4",
                    "kind": "review",
                    "options": [{"id": "continue", "label": "继续"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["action"],
                        "properties": {
                            "action": {"type": "string"},
                            "selected_targets": {"type": "array"},
                        },
                    },
                    "selection_options": [
                        {"coord": "com.example:demo-lib", "name": "demo-lib"},
                    ],
                    "input_normalization": {"enabled": True},
                },
                "step4",
                project_dir=project_dir,
                report_dir=report_dir,
            )

            updated_state, _ = run_step.apply_user_response_to_main_state(
                state,
                pending_interaction,
                {
                    "intent_patch": {
                        "action": "continue",
                        "set": {"selected_targets": ["com.example:demo-lib"]},
                    }
                },
                project_dir,
                target_step_id="step4",
            )
            run_step.handle_step4_resume_followups(
                updated_state,
                report_dir,
                "step4",
                "continue",
            )

        self.assertEqual(
            updated_state["step4"]["input"]["step5_selected_coords"],
            ["com.example:demo-lib"],
        )
        self.assertEqual(
            updated_state["step5"]["input"]["step5_selected_coords"],
            ["com.example:demo-lib"],
        )

    def test_partial_scope_keeps_two_selected_dependencies_out_of_eighty_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            selected = [
                "org.apache.seata:seata-common",
                "net.sf.json-lib:json-lib:jdk15",
            ]
            coords = selected + [
                f"com.example:dependency-{index:02d}" for index in range(79)
            ]
            rows = [
                {
                    "coord": coord,
                    "class_name": "com.example.Demo",
                    "member": "run()",
                }
                for coord in coords
            ]
            selection_options = run_step.build_interaction_selection_options(
                [
                    {
                        "coord": coord,
                        "name": run_step._artifact_name_from_coord(coord),
                    }
                    for coord in coords
                ]
            )
            interaction = run_step.apply_interaction_protocol_enhancements(
                {
                    "step_id": "step4",
                    "kind": "review",
                    "options": [{"id": "continue", "label": "继续"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["action"],
                        "properties": {"action": {"type": "string"}},
                    },
                    "selection_options": selection_options,
                },
                "step4",
            )
            response = {
                "intent_patch": {
                    "action": "continue",
                    "set": {
                        "scope_mode": "partial",
                        "selected_targets": selected,
                    },
                }
            }
            canonical = run_step.build_canonical_user_response(response)
            run_step.validate_pending_interaction_response(interaction, canonical)
            state = run_step.new_main_state(report_dir)

            _, context = run_step.apply_user_response_to_main_state(
                state,
                interaction,
                response,
                project_dir,
                target_step_id="step4",
            )
            summary = run_step.build_step5_selection_summary(
                rows,
                selected_coords=context.get("step5_selected_coords"),
                selected_names=context.get("step5_selected_names"),
            )

        self.assertEqual(context["step5_scope_mode"], "partial")
        self.assertEqual(context["step5_selected_coords"], selected)
        self.assertEqual(
            {row["coord"] for row in summary["matched_rows"]},
            set(selected),
        )
        self.assertEqual(summary["available_target_count"], 81)
        self.assertEqual(summary["matched_row_count"], 2)

    def test_build_interaction_payload_step4_keeps_full_selection_resolution_when_display_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            self._api_changes_dir(report_dir).mkdir(parents=True)
            with (self._api_changes_dir(report_dir) / "all_changed_apis.csv").open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=["coord", "class_name", "member"])
                writer.writeheader()
                for idx in range(21):
                    writer.writerow(
                        {
                            "coord": f"com.example:demo-lib-{idx:02d}",
                            "class_name": f"com.example.Demo{idx}",
                            "member": "run()",
                        }
                    )
            manifest_steps = {
                "step4": {
                    "interaction": {
                        "title": "请确认",
                        "question": "请确认",
                        "options": [{"id": "continue", "label": "继续", "description": "继续"}],
                    },
                    "outputs": ["evidence/api_changes/all_changed_apis.csv"],
                }
            }

            payload = run_step.build_interaction_payload(
                "step4",
                report_dir,
                manifest_steps,
                project_dir,
                run_context={},
                main_state=run_step.new_main_state(report_dir),
            )

        self.assertEqual(len(payload["selection_options"]), 10)
        self.assertEqual(len(payload["selection_resolution"]["options"]), 21)
        self.assertEqual(
            payload["selection_resolution"]["options"][-1]["selection_key"],
            "coord:com.example:demo-lib-20",
        )

    def test_apply_user_response_to_main_state_resolves_selected_targets_outside_display_slice(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            full_selection_options = run_step.build_interaction_selection_options(
                [
                    {
                        "coord": f"com.example:demo-lib-{idx:02d}",
                        "name": f"demo-lib-{idx:02d}",
                    }
                    for idx in range(21)
                ]
            )
            pending_interaction = run_step.apply_interaction_protocol_enhancements(
                {
                    "step_id": "step4",
                    "kind": "review",
                    "options": [{"id": "continue", "label": "继续"}],
                    "response_schema": {
                        "type": "object",
                        "required": ["action"],
                        "properties": {
                            "action": {"type": "string"},
                            "selected_targets": {"type": "array"},
                        },
                    },
                    "selection_options": full_selection_options[:20],
                    "selection_resolution": run_step.build_selection_resolution(full_selection_options),
                    "input_normalization": {"enabled": True},
                },
                "step4",
                project_dir=project_dir,
                report_dir=report_dir,
            )

            updated_state, _ = run_step.apply_user_response_to_main_state(
                state,
                pending_interaction,
                {
                    "intent_patch": {
                        "action": "continue",
                        "set": {"selected_targets": ["com.example:demo-lib-20"]},
                    }
                },
                project_dir,
                target_step_id="step4",
            )
            run_step.handle_step4_resume_followups(
                updated_state,
                report_dir,
                "step4",
                "continue",
            )

        self.assertEqual(
            updated_state["step4"]["input"]["step5_selected_coords"],
            ["com.example:demo-lib-20"],
        )
        self.assertEqual(
            updated_state["step5"]["input"]["step5_selected_coords"],
            ["com.example:demo-lib-20"],
        )

    def test_apply_user_response_to_main_state_accepts_strict_risk_gate_intent_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            pending_interaction = {
                "step_id": "step5",
                "kind": "review",
                "response_schema": {
                    "type": "object",
                    "required": ["action"],
                    "properties": {
                        "action": {"type": "string"},
                        "strict_risk_gate": {"type": "boolean"},
                    },
                },
            }

            updated_state, updated_context = run_step.apply_user_response_to_main_state(
                state,
                pending_interaction,
                {
                    "intent_patch": {
                        "action": "continue",
                        "set": {"strict_risk_gate": True},
                    }
                },
                project_dir,
                target_step_id="step5",
            )

        self.assertTrue(updated_context["strict_risk_gate"])
        self.assertTrue(updated_state["step5"]["input"]["strict_risk_gate"])


    def test_execute_step5_passes_validated_selected_targets_to_binary_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = self._api_changes_dir(report_dir)
            s4_dir.mkdir(parents=True)
            with open(s4_dir / "all_changed_apis.csv", "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=run_step.ALL_CHANGED_APIS_FIELDS)
                writer.writeheader()
                for row in [
                    {
                        "coord": "com.example:demo-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Demo.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "classfile_contract",
                    },
                    {
                        "coord": "com.example:core-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Core.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "classfile_contract",
                    },
                    {
                        "coord": "com.example:other-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Other.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "classfile_contract",
                    },
                ]:
                    writer.writerow(row)
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "step5_selected_coords": ["com.example:demo-lib"],
                "step5_selected_names": ["core-lib"],
            }
            manifest_steps = {"step5": {"gate": "binary_report"}}
            captured = {}

            def fake_publish(**kwargs):
                captured.update(kwargs)
                return {"elapsed_seconds": 0.01}

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "require_current_release_stage"), \
                 patch.object(
                     run_step,
                     "_run_downstream_report_publication",
                     side_effect=fake_publish,
                 ), \
                 patch.object(run_step, "build_interaction_payload", return_value={}), \
                patch.object(run_step, "build_run_context", return_value=run_context):
                run_step.execute_step("step5", args, manifest_steps, run_context)
            timing_path = report_dir / ".runtime/observability/step5_timing.csv"
            self.assertTrue(timing_path.read_bytes().startswith(b"\xef\xbb\xbf"))

        self.assertEqual(captured["stage"], "step5")
        self.assertEqual(
            captured["selected_coords"], ("com.example:demo-lib",)
        )
        self.assertEqual(captured["selected_names"], ("core-lib",))

    def test_materialize_step5_rejects_partial_scope_without_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            all_changed_path = (
                self._api_changes_dir(report_dir) / "all_changed_apis.csv"
            )
            all_changed_path.parent.mkdir(parents=True)
            with all_changed_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=run_step.ALL_CHANGED_APIS_FIELDS,
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "com.example:demo-lib",
                        "api_name": "com.example.Demo.call",
                        "api_simple": "call",
                        "api_signature": "()",
                        "symbol_kind": "method",
                        "change_type": "REMOVED",
                    }
                )

            with self.assertRaisesRegex(
                run_step.StepError,
                "不能静默回退为全量分析",
            ):
                run_step.materialize_step5_all_changed_apis_input(
                    all_changed_path,
                    report_dir,
                    {"step5_scope_mode": "partial"},
                )

    def test_execute_step5_rejects_unmatched_selected_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            s4_dir = self._api_changes_dir(report_dir)
            s4_dir.mkdir(parents=True)
            with open(s4_dir / "all_changed_apis.csv", "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=run_step.ALL_CHANGED_APIS_FIELDS)
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "com.example:demo-lib",
                        "old_version": "1.0.0",
                        "new_version": "2.0.0",
                        "change_type": "REMOVED",
                        "api_name": "com.example.Demo.call",
                        "api_simple": "call",
                        "symbol_kind": "method",
                        "api_signature": "()",
                        "confirmed": "true",
                        "severity": "P0",
                        "source": "classfile_contract",
                    }
                )
            args = self._make_default_args(project_dir, report_dir)
            run_context = {
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "source_dirs_status": "provided",
                "dependency_source_mappings": [],
                "step5_selected_coords": ["com.example:not-found"],
            }
            manifest_steps = {"step5": {"gate": "binary_report"}}

            with patch.object(run_step, "validate_run_context_for_step"), \
                 patch.object(run_step, "require_current_release_stage"), \
                 patch.object(
                     run_step,
                     "_run_downstream_report_publication",
                     side_effect=run_step.StepError(
                         "BINARY_STEP5_SELECTION_UNMATCHED"
                     ),
                 ), \
                 patch.object(run_step, "build_interaction_payload", return_value={}):
                with self.assertRaises(run_step.StepError):
                    run_step.execute_step("step5", args, manifest_steps, run_context)


    def test_build_run_context_expands_path_only_dependency_repo_mappings(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            dep_repo = project_dir / "demo-lib-repo"
            (dep_repo / "src" / "main" / "java").mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>demo-lib</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )
            self._write_text(run_step.step1_dep_changes_path(report_dir),
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            args = self._make_default_args(project_dir, report_dir)

            run_context = run_step.build_run_context(
                args,
                {},
                {"dependency_repo_mappings": [str(dep_repo)]},
            )

        self.assertEqual(
            run_context["dependency_repo_mappings"],
            [f"com.example:demo-lib={dep_repo.resolve()}"],
        )

    def test_dependency_source_plan_expands_module_ga_to_classifier_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            dep_repo = Path(tmp) / "native-repo"
            source_dir = dep_repo / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>native</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )

            plan = run_step._build_dependency_source_plan(
                [str(dep_repo)],
                relevant_coords=[
                    "com.example:native:osx-aarch_64",
                    "com.example:native:osx-x86_64",
                ],
            )

        self.assertEqual(
            plan["dependency_repo_mappings"],
            [
                f"com.example:native:osx-aarch_64={dep_repo.resolve()}",
                f"com.example:native:osx-x86_64={dep_repo.resolve()}",
            ],
        )
        self.assertEqual(
            plan["dependency_source_mappings"],
            [
                f"com.example:native:osx-aarch_64={source_dir.resolve()}",
                f"com.example:native:osx-x86_64={source_dir.resolve()}",
            ],
        )
        self.assertEqual(plan["unmatched_relevant_coords"], [])

    def test_build_run_context_expands_group_prefix_dependency_repo_mappings(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            dep_repo = project_dir / "demo-lib-repo"
            (dep_repo / "src" / "main" / "java").mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>demo-lib</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )
            self._write_text(run_step.step1_dep_changes_path(report_dir),
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            args = self._make_default_args(project_dir, report_dir)

            run_context = run_step.build_run_context(
                args,
                {},
                {"dependency_repo_mappings": [{"coord": "com.example", "path": str(dep_repo)}]},
            )

        self.assertEqual(
            run_context["dependency_repo_mappings"],
            [f"com.example:demo-lib={dep_repo.resolve()}"],
        )

    def test_main_loads_seed_json_before_building_step4_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            (project_dir / "src" / "main" / "java").mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            dep_repo = project_dir / "demo-lib-repo"
            (dep_repo / "src" / "main" / "java").mkdir(parents=True)
            (dep_repo / "pom.xml").write_text(
                (
                    "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">"
                    "<modelVersion>4.0.0</modelVersion>"
                    "<groupId>com.example</groupId>"
                    "<artifactId>demo-lib</artifactId>"
                    "<version>1.0.0</version>"
                    "</project>"
                ),
                encoding="utf-8",
            )
            self._write_text(run_step.step1_dep_changes_path(report_dir),
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            seed_json_path = report_dir / "main_state_seed.json"
            seed_json_path.write_text(
                f"{{\"dependency_repo_mappings\":[\"{dep_repo}\"]}}",
                encoding="utf-8",
            )
            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                return None

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "step4",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                    "--seed-json",
                    str(seed_json_path),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step4": {"gate": "binary_diff"}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ), patch.object(
                run_step,
                "_recover_and_apply_step4_startup_state",
                return_value={
                    "action": run_step._STEP4_RELEASE_CURRENT,
                    "applied": False,
                    "forced_step_id": "",
                    "discard_structured_response": False,
                },
            ), patch.object(
                run_step,
                "_apply_downstream_release_startup_state",
                return_value={
                    "forced_step_id": "",
                    "discard_structured_response": False,
                    "release": {},
                },
            ):
                exit_code = run_step.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["step_id"], "step4")
        self.assertEqual(
            captured["run_context"]["dependency_repo_mappings"],
            [f"com.example:demo-lib={dep_repo.resolve()}"],
        )

    def test_build_run_context_prefers_existing_main_state_over_seed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            args = self._make_default_args(project_dir, report_dir)

            run_context = run_step.build_run_context(
                args,
                {"base_branch": "from-main-state", "current_branch": "feature/a"},
                {"base_branch": "from-runtime-config", "current_branch": "feature/b"},
                allow_external_seed=False,
            )

        self.assertEqual(run_context["base_branch"], "from-main-state")
        self.assertEqual(run_context["current_branch"], "feature/a")

    def test_execute_step4_does_not_pass_git_ref_overrides_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            self._write_text(run_step.step1_dep_changes_path(report_dir), 
                "coord,change_type,resolution_status,old_version,new_version\n"
                "com.example:demo-lib,升级,resolved,1.0.0,2.0.0\n",
                encoding="utf-8",
            )
            self._write_text(run_step.step2_context_path(report_dir), "{}", encoding="utf-8")
            config = project_dir / "binary.json"
            config.write_text("{}", encoding="utf-8")
            args = self._make_default_args(project_dir, report_dir)
            captured = []

            def fake_run_python(script_name, script_args, *_args, **_kwargs):
                captured.append((script_name, list(script_args)))
                self.assertEqual(script_name, "binary_pipeline.py")
                self._write_fake_step4_pipeline_result(script_args)
                return None

            def prepare_report(**kwargs):
                return self._fake_step4_report_result(kwargs["report_dir"])

            with patch.object(run_step, "validate_run_context_for_step"), \
                    patch.object(
                        run_step,
                        "materialize_pinned_source_workspace",
                        return_value=nullcontext({
                            "source_dirs": [str(source_dir.resolve())],
                            "project_root": project_dir,
                        }),
                    ), patch.object(
                        run_step,
                        "materialize_pinned_dependency_source_workspaces",
                        side_effect=lambda context, _report: nullcontext(context),
                    ), patch.object(
                        run_step, "run_python", side_effect=fake_run_python
                    ), patch.object(
                        run_step,
                        "_prepare_binary_report_publication_candidate_in_process",
                        side_effect=prepare_report,
                    ), patch.object(
                        run_step,
                        "_complete_binary_step4_after_gate",
                        return_value=True,
                    ):
                run_step.execute_step(
                    "step4",
                    args,
                    {"step4": {"gate": "binary_generation"}},
                    {
                        "step0_confirmed": True,
                        "base_branch": "main",
                        "current_branch": "feature/upgrade",
                        "source_dirs": [str(source_dir.resolve())],
                        "source_dirs_status": "provided",
                        "binary_pipeline_config": str(config),
                        "dependency_git_ref_overrides": [
                            {
                                "coord": "com.example:demo-lib",
                                "old_ref": "v1.0.0",
                                "new_ref": "v2.0.0",
                            }
                        ],
                    },
                )

        s4_calls = [item for item in captured if item[0] == "binary_pipeline.py"]
        self.assertEqual(len(s4_calls), 1)
        _, script_args = s4_calls[0]
        self.assertNotIn("--dependency-git-ref-overrides-json", script_args)

    def test_cleanup_step_outputs_only_removes_current_step_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            step2_context = run_step.step2_context_path(report_dir)
            step2_graph = run_step.step2_dep_graph_path(report_dir)
            step1_output = run_step.step1_dep_changes_path(report_dir)
            main_state = run_step.main_state_path(report_dir)
            interaction = self._runtime_state_dir(report_dir) / "interaction.json"
            self._write_text(step2_context, "{}", encoding="utf-8")
            self._write_text(step2_graph, "{}", encoding="utf-8")
            self._write_text(step1_output, "coord", encoding="utf-8")
            self._write_text(main_state, "{}", encoding="utf-8")
            self._write_text(interaction, "{}", encoding="utf-8")

            run_step.cleanup_step_outputs("step2", report_dir)

            self.assertFalse(step2_context.exists())
            self.assertFalse(step2_graph.exists())
            self.assertTrue(step1_output.exists())
            self.assertTrue(main_state.exists())
            self.assertTrue(interaction.exists())

    def test_cleanup_step_outputs_removes_all_step1_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            step1_alerts = run_step.step1_dep_alerts_path(report_dir)
            step1_changes = run_step.step1_dep_changes_path(report_dir)
            step1_summary = run_step.step1_dep_summary_path(report_dir)
            step1_resolved = run_step.step1_current_resolved_path(report_dir)
            build_provenance = run_step.build_provenance_path(report_dir)
            artifacts_dir = run_step.step1_artifacts_dir(report_dir)
            main_state = run_step.main_state_path(report_dir)
            interaction = self._runtime_state_dir(report_dir) / "interaction.json"
            self._write_text(step1_alerts, "coord\n", encoding="utf-8")
            self._write_text(step1_changes, "coord\n", encoding="utf-8")
            self._write_text(step1_summary, "summary\n", encoding="utf-8")
            self._write_text(step1_resolved, "coord\n", encoding="utf-8")
            self._write_text(build_provenance, "{}", encoding="utf-8")
            artifacts_dir.mkdir(parents=True)
            (artifacts_dir / "current.jar").write_text("jar\n", encoding="utf-8")
            self._write_text(main_state, "{}", encoding="utf-8")
            self._write_text(interaction, "{}", encoding="utf-8")

            run_step.cleanup_step_outputs("step1", report_dir)

            self.assertFalse(step1_alerts.exists())
            self.assertFalse(step1_changes.exists())
            self.assertFalse(step1_summary.exists())
            self.assertFalse(step1_resolved.exists())
            self.assertFalse(build_provenance.exists())
            self.assertFalse(artifacts_dir.exists())
            self.assertTrue(main_state.exists())
            self.assertTrue(interaction.exists())

    def test_cleanup_step_outputs_never_traverses_parent_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            external = root / "external-context"
            external.mkdir()
            external_context = external / "context.json"
            external_graph = external / "dep_graph.json"
            external_context.write_text("outside", encoding="utf-8")
            external_graph.write_text("outside", encoding="utf-8")
            evidence = report_dir / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "context").symlink_to(
                external, target_is_directory=True
            )

            with self.assertRaises(run_step.StepError) as caught:
                run_step.cleanup_step_outputs("step2", report_dir)

            self.assertIn(
                "WORKFLOW_OUTPUT_CLEANUP_PATH_UNSAFE",
                caught.exception.reason_codes,
            )
            self.assertEqual(
                external_context.read_text(encoding="utf-8"), "outside"
            )
            self.assertEqual(
                external_graph.read_text(encoding="utf-8"), "outside"
            )
            self.assertTrue((evidence / "context").is_symlink())

    def test_cleanup_step_outputs_unlinks_leaf_symlink_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            context = run_step.step2_context_path(report_dir)
            context.parent.mkdir(parents=True)
            external = root / "external-context.json"
            external.write_text("outside", encoding="utf-8")
            context.symlink_to(external)

            run_step.cleanup_step_outputs("step2", report_dir)

            self.assertFalse(context.exists())
            self.assertFalse(context.is_symlink())
            self.assertEqual(
                external.read_text(encoding="utf-8"), "outside"
            )

    def test_cleanup_step_outputs_directory_tree_unlinks_nested_symlink_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            artifacts = run_step.step1_artifacts_dir(report_dir)
            nested = artifacts / "nested"
            nested.mkdir(parents=True)
            (nested / "inside.jar").write_text("inside", encoding="utf-8")
            external = root / "external.jar"
            external.write_text("outside", encoding="utf-8")
            (nested / "outside-link.jar").symlink_to(external)

            run_step.cleanup_step_outputs("step1", report_dir)

            self.assertFalse(artifacts.exists())
            self.assertEqual(external.read_text(encoding="utf-8"), "outside")

    @unittest.skipUnless(
        run_step._secure_step_output_cleanup_supported(),
        "descriptor-relative cleanup requires POSIX dir_fd support",
    )
    def test_cleanup_step_outputs_parent_swap_cannot_delete_external_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_dir = root / "report"
            context_dir = report_dir / "evidence" / "context"
            context_dir.mkdir(parents=True)
            original_context = context_dir / "context.json"
            original_context.write_text("inside", encoding="utf-8")
            moved_context = context_dir.with_name("context-original")
            external = root / "external-context"
            external.mkdir()
            external_context = external / "context.json"
            external_context.write_text("outside", encoding="utf-8")
            real_unlink = os.unlink
            raced = False

            def swap_parent_before_unlink(name, *args, **kwargs):
                nonlocal raced
                if (
                    not raced
                    and name == "context.json"
                    and kwargs.get("dir_fd") is not None
                ):
                    raced = True
                    context_dir.rename(moved_context)
                    context_dir.symlink_to(
                        external, target_is_directory=True
                    )
                return real_unlink(name, *args, **kwargs)

            with patch.object(
                run_step,
                "_secure_step_output_cleanup_supported",
                return_value=True,
            ), patch.object(
                run_step.os,
                "unlink",
                side_effect=swap_parent_before_unlink,
            ):
                with self.assertRaises(run_step.StepError) as caught:
                    run_step.cleanup_step_outputs("step2", report_dir)

            self.assertTrue(raced)
            self.assertIn(
                "WORKFLOW_OUTPUT_CLEANUP_PATH_UNSAFE",
                caught.exception.reason_codes,
            )
            self.assertEqual(
                external_context.read_text(encoding="utf-8"), "outside"
            )
            self.assertFalse((moved_context / "context.json").exists())
            self.assertTrue(context_dir.is_symlink())

    @unittest.skipUnless(
        run_step._secure_step_output_cleanup_supported(),
        "checkpoint reads require POSIX dir_fd support",
    )
    def test_step4_checkpoint_root_swap_cannot_redirect_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report"
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text(
                '{"status": "inside"}\n', encoding="utf-8"
            )
            moved_report = root / "report-original"
            replacement = root / "replacement-report"
            replacement_checkpoint = (
                replacement
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / "binary_observability"
                / "validation_checkpoint.json"
            )
            replacement_checkpoint.parent.mkdir(parents=True)
            replacement_checkpoint.write_text(
                '{"status": "outside"}\n', encoding="utf-8"
            )
            original_read = run_step._read_private_step4_checkpoint
            raced = False

            def swap_root_then_read(entry, *, parent_fd=None):
                nonlocal raced
                if parent_fd is not None and not raced:
                    raced = True
                    report.rename(moved_report)
                    replacement.rename(report)
                return original_read(entry, parent_fd=parent_fd)

            with patch.object(
                run_step,
                "_read_private_step4_checkpoint",
                side_effect=swap_root_then_read,
            ), self.assertRaises(run_step.StepError) as caught:
                run_step._read_step4_validation_checkpoint(report)

            self.assertTrue(raced)
            self.assertIn(
                "BINARY_STEP4_TRANSACTION_CHECKPOINT_INVALID",
                caught.exception.reason_codes,
            )
            self.assertEqual(
                (
                    report
                    / run_step.BINARY_OUTPUT_RELATIVE_PATH
                    / "binary_observability"
                    / "validation_checkpoint.json"
                ).read_text(encoding="utf-8"),
                '{"status": "outside"}\n',
            )
            self.assertEqual(
                (
                    moved_report
                    / run_step.BINARY_OUTPUT_RELATIVE_PATH
                    / "binary_observability"
                    / "validation_checkpoint.json"
                ).read_text(encoding="utf-8"),
                '{"status": "inside"}\n',
            )

    def test_step4_checkpoint_reader_rejects_non_strict_and_oversized_json(self):
        invalid_payloads = (
            b'{"status":"first","status":"second"}\n',
            b'{"status":NaN}\n',
            b'{"status":"oversized"}\n',
        )
        for index, payload in enumerate(invalid_payloads):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp:
                report = Path(tmp) / "report"
                checkpoint = run_step._step4_validation_checkpoint_path(report)
                checkpoint.parent.mkdir(parents=True)
                checkpoint.write_bytes(payload)
                size_limit = (
                    len(payload) - 1
                    if index == len(invalid_payloads) - 1
                    else run_step._STEP4_VALIDATION_CHECKPOINT_MAX_BYTES
                )

                with patch.object(
                    run_step,
                    "_STEP4_VALIDATION_CHECKPOINT_MAX_BYTES",
                    size_limit,
                ), self.assertRaises(run_step.StepError) as caught:
                    run_step._read_step4_validation_checkpoint(report)

                self.assertIn(
                    "BINARY_STEP4_TRANSACTION_CHECKPOINT_INVALID",
                    caught.exception.reason_codes,
                )

    @unittest.skipUnless(
        run_step._secure_step_output_cleanup_supported(),
        "checkpoint deletion requires POSIX dir_fd support",
    )
    def test_step4_checkpoint_parent_swap_cannot_delete_external_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report"
            checkpoint = run_step._step4_validation_checkpoint_path(report)
            checkpoint.parent.mkdir(parents=True)
            checkpoint.write_text("inside\n", encoding="utf-8")
            moved_parent = checkpoint.parent.with_name(
                "binary_observability-original"
            )
            external = root / "external-observability"
            external.mkdir()
            external_checkpoint = external / "validation_checkpoint.json"
            external_checkpoint.write_text("outside\n", encoding="utf-8")
            real_unlink = os.unlink
            real_rename = os.rename
            raced = False

            def swap_parent_before_unlink(name, *args, **kwargs):
                nonlocal raced
                if (
                    not raced
                    and name == "validation_checkpoint.json"
                    and kwargs.get("dir_fd") is not None
                ):
                    raced = True
                    real_rename(checkpoint.parent, moved_parent)
                    checkpoint.parent.symlink_to(
                        external, target_is_directory=True
                    )
                return real_unlink(name, *args, **kwargs)

            with patch.object(
                run_step,
                "_secure_step_output_cleanup_supported",
                return_value=True,
            ), patch.object(
                run_step.os,
                "unlink",
                side_effect=swap_parent_before_unlink,
            ), self.assertRaises(run_step.StepError) as caught:
                run_step._delete_step4_validation_checkpoint_durable(
                    checkpoint
                )

            self.assertTrue(raced)
            self.assertIn(
                "BINARY_STEP4_TRANSACTION_CHECKPOINT_INVALID",
                caught.exception.reason_codes,
            )
            self.assertEqual(
                external_checkpoint.read_text(encoding="utf-8"), "outside\n"
            )
            self.assertFalse(
                (moved_parent / "validation_checkpoint.json").exists()
            )
            self.assertTrue(checkpoint.parent.is_symlink())

    @unittest.skipIf(os.name == "nt", "POSIX capability fallback contract")
    def test_cleanup_step_outputs_fails_closed_without_secure_primitives(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            context = run_step.step2_context_path(report_dir)
            context.parent.mkdir(parents=True)
            context.write_text("inside", encoding="utf-8")

            with patch.object(
                run_step,
                "_secure_step_output_cleanup_supported",
                return_value=False,
            ):
                with self.assertRaises(run_step.StepError) as caught:
                    run_step.cleanup_step_outputs("step2", report_dir)

            self.assertIn(
                "WORKFLOW_OUTPUT_CLEANUP_PATH_UNSAFE",
                caught.exception.reason_codes,
            )
            self.assertEqual(context.read_text(encoding="utf-8"), "inside")


    def test_cleanup_step_outputs_step3_does_not_mutate_committed_step4_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            risk_candidates = self._static_scan_dir(report_dir) / run_step.STEP3_RISK_CANDIDATES_FILE
            risk_candidates.parent.mkdir(parents=True, exist_ok=True)
            risk_candidates.write_text("coord\n", encoding="utf-8")
            database_contract_files = [
                self._static_scan_dir(report_dir) / "s3_database_contract_changes.csv",
                self._static_scan_dir(report_dir) / "s3_database_contract_summary.json",
                self._static_scan_dir(report_dir) / "s3_database_contract_changes.md",
            ]
            for path in database_contract_files:
                path.write_text("stale\n", encoding="utf-8")
            per_dep_dir = self._api_changes_dir(report_dir) / run_step.PER_DEPENDENCY_DIRNAME / "sample_demo"
            per_dep_dir.mkdir(parents=True)
            candidate_hits = per_dep_dir / "candidate_hits.csv"
            candidate_hits.write_text("coord\nsample:demo\n", encoding="utf-8")
            summary_path = per_dep_dir / "summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "coord": "sample:demo",
                        "step3": {"candidate_hit_count": 1},
                        "step4": {"target_count": 2},
                        "artifacts": {
                            "candidate_hits_csv": str(candidate_hits),
                            "resolved_targets_csv": "resolved_targets.csv",
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            run_step.cleanup_step_outputs("step3", report_dir)

            self.assertFalse(risk_candidates.exists())
            self.assertTrue(all(not path.exists() for path in database_contract_files))
            self.assertTrue(candidate_hits.exists())
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["step3"]["candidate_hit_count"], 1)
            self.assertEqual(summary["step4"]["target_count"], 2)
            self.assertIn("candidate_hits_csv", summary["artifacts"])

    def test_main_explicit_step_run_resets_current_and_downstream_state_and_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            source_dir = project_dir / "src" / "main" / "java"
            source_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            state["state"]["completed_step"] = "step6"
            state["state"]["status"] = "completed"
            state["step2"]["output"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str(source_dir.resolve())],
            }
            state["step3"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str(source_dir.resolve())],
            }
            state["step3"]["output"] = {"summary": "stale-step3"}
            state["step4"]["input"] = {"dependency_source_dirs": [str((project_dir / "dep-repo").resolve())]}
            state["step4"]["output"] = {"summary": "stale-step4"}
            state["step5"]["output"] = {"summary": "stale-step5"}
            state["step6"]["output"] = {"report": "stale-step6"}
            run_step.save_main_state(report_dir, state)

            self._write_text(run_step.step1_dep_changes_path(report_dir), "coord\n", encoding="utf-8")
            self._write_text(self._static_scan_dir(report_dir) / "s3_jdk_removed_api.csv", "symbol\n", encoding="utf-8")
            self._api_changes_dir(report_dir).mkdir()
            (self._api_changes_dir(report_dir) / "all_changed_apis.csv").write_text("coord\n", encoding="utf-8")
            self._call_chain_dir(report_dir).mkdir()
            (self._call_chain_dir(report_dir) / "summary.json").write_text("{}", encoding="utf-8")
            self._write_text(run_step.s6_findings_path(report_dir), "{}", encoding="utf-8")
            self._write_text(run_step.final_report_path(report_dir), "# stale\n", encoding="utf-8")

            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                captured["state"] = run_step.load_main_state(report_dir)
                captured["step1_output_exists"] = (run_step.step1_dep_changes_path(report_dir)).exists()
                captured["step3_output_exists"] = (self._static_scan_dir(report_dir) / "s3_jdk_removed_api.csv").exists()
                captured["step4_output_exists"] = self._api_changes_dir(report_dir).exists()
                captured["step5_output_exists"] = self._call_chain_dir(report_dir).exists()
                captured["step6_findings_exists"] = run_step.s6_findings_path(report_dir).exists()
                captured["step6_report_exists"] = run_step.final_report_path(report_dir).exists()
                return None

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "step3",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step3": {"gate": "context_build"}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ):
                exit_code = run_step.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["step_id"], "step3")
        self.assertEqual(captured["run_context"]["base_branch"], "base")
        self.assertEqual(captured["run_context"]["current_branch"], "current")
        self.assertEqual(captured["run_context"]["source_dirs"], [str(source_dir.resolve())])
        self.assertFalse(captured["step3_output_exists"])
        self.assertTrue(captured["step4_output_exists"])
        self.assertTrue(captured["step5_output_exists"])
        self.assertTrue(captured["step6_findings_exists"])
        self.assertTrue(captured["step6_report_exists"])
        self.assertTrue(captured["step1_output_exists"])
        self.assertEqual(captured["state"]["state"]["current_step"], "step3")
        self.assertEqual(captured["state"]["state"]["completed_step"], "step2")
        self.assertEqual(captured["state"]["state"]["status"], "ready")
        self.assertEqual(
            captured["state"]["step3"]["input"]["source_dirs"],
            [str(source_dir.resolve())],
        )
        self.assertEqual(captured["state"]["step3"]["output"], {})
        self.assertEqual(captured["state"]["step4"], run_step.empty_step_state())
        self.assertEqual(captured["state"]["step5"], run_step.empty_step_state())
        self.assertEqual(captured["state"]["step6"], run_step.empty_step_state())
        self.assertEqual(
            captured["state"]["step2"]["output"]["source_dirs"],
            [str(source_dir.resolve())],
        )


    def test_main_auto_repairs_missing_step4_prereq_by_restarting_step1(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            (project_dir / "src" / "main" / "java").mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "step4"
            state["state"]["completed_step"] = "step3"
            state["step1"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "analysis_mode": "checkout_build",
                "target_module": ".",
            }
            state["step2"]["output"] = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
            }
            state["step3"]["output"] = dict(state["step2"]["output"])
            run_step.save_main_state(report_dir, state)
            self._write_text(run_step.step2_context_path(report_dir), "{}", encoding="utf-8")
            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                return None

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "auto",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step1": {}, "step4": {}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ), patch.object(
                run_step,
                "resolve_step1_refs_for_execution",
                side_effect=lambda context, _project, **_kwargs: (dict(context), None),
            ):
                exit_code = run_step.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["step_id"], "step1")
        self.assertEqual(captured["run_context"]["base_branch"], "base")
        self.assertEqual(captured["run_context"]["current_branch"], "current")

    def test_main_auto_bridges_non_pending_intent_when_current_step_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            (project_dir / "src" / "main" / "java").mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            state["state"]["completed_step"] = "step6"
            state["step5"]["input"] = {
                "base_branch": "base",
                "current_branch": "current",
            }
            run_step.save_main_state(report_dir, state)
            self._api_changes_dir(report_dir).mkdir(parents=True, exist_ok=True)
            (self._api_changes_dir(report_dir) / "all_changed_apis.csv").write_text(
                "coord,class_name,member\ncom.example:demo-lib,com.example.Demo,run()\n",
                encoding="utf-8",
            )
            dependencies_dir = report_dir / "evidence" / "dependencies"
            dependencies_dir.mkdir(parents=True, exist_ok=True)
            (dependencies_dir / "dep_changes.csv").write_text(
                "coord,old_version,new_version\ncom.example:demo-lib,1,2\n",
                encoding="utf-8",
            )
            context_dir = report_dir / "evidence" / "context"
            context_dir.mkdir(parents=True, exist_ok=True)
            (context_dir / "context.json").write_text("{}\n", encoding="utf-8")
            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                return None

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "auto",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                    "--response-json",
                    json.dumps(
                        {
                            "intent_patch": {
                                "action": "continue",
                                "set": {
                                    "selected_targets": ["com.example:demo-lib"],
                                },
                            }
                        },
                        ensure_ascii=False,
                    ),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step5": {"gate": "binary_report"}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ), patch.object(
                run_step,
                "_recover_and_apply_step4_startup_state",
                return_value={
                    "action": run_step._STEP4_RELEASE_CURRENT,
                    "applied": False,
                    "forced_step_id": "",
                    "discard_structured_response": False,
                },
            ), patch.object(
                run_step,
                "_apply_downstream_release_startup_state",
                return_value={
                    "forced_step_id": "",
                    "discard_structured_response": False,
                    "release": {},
                },
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)
            self.assertEqual(exit_code, 0)
            self.assertEqual(captured["step_id"], "step5")
            self.assertEqual(
                captured["run_context"]["step5_selected_coords"],
                ["com.example:demo-lib"],
            )
            self.assertEqual(saved["state"]["current_step"], "step6")
            self.assertEqual(saved["state"]["completed_step"], "step5")

    def test_main_auto_restarts_from_step_after_pipeline_done_without_business_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            project_dir.mkdir(parents=True)
            report_dir = project_dir / ".upgrade-report"
            report_dir.mkdir(parents=True)
            state = run_step.new_main_state(report_dir)
            state["state"]["current_step"] = "done"
            state["state"]["completed_step"] = "step6"
            base_context = {
                "base_branch": "base",
                "current_branch": "current",
                "source_dirs": [str((project_dir / "src/main/java").resolve())],
                "analysis_mode": "checkout_build",
                "target_module": ".",
            }
            state["step1"]["output"] = dict(base_context)
            state["step2"]["output"] = dict(base_context)
            state["step3"]["output"] = dict(base_context)
            state["step4"]["input"] = dict(base_context)
            state["step4"]["output"] = dict(base_context)
            state["step5"]["output"] = {"stale": True}
            state["step6"]["output"] = {"stale": True}
            run_step.save_main_state(report_dir, state)

            self._write_text(run_step.step1_dep_changes_path(report_dir), 
                "change_type,group_id,artifact_id,base_version,current_version\n",
                encoding="utf-8",
            )
            self._write_text(run_step.step2_context_path(report_dir), "{}", encoding="utf-8")
            self._api_changes_dir(report_dir).mkdir(parents=True, exist_ok=True)
            (self._api_changes_dir(report_dir) / "all_changed_apis.csv").write_text(
                "coord,class_name,member\ncom.example:demo,com.example.Demo,run()\n",
                encoding="utf-8",
            )
            self._call_chain_dir(report_dir).mkdir(parents=True, exist_ok=True)
            (self._call_chain_dir(report_dir) / "alerts.csv").write_text("x\n", encoding="utf-8")
            self._write_text(run_step.final_report_path(report_dir), "# stale\n", encoding="utf-8")
            captured = {}

            def fake_execute_step(step_id, _args, _manifest_steps, run_context, **_kwargs):
                captured["step_id"] = step_id
                captured["run_context"] = dict(run_context)
                captured["s4_exists_before_step"] = self._api_changes_dir(report_dir).exists()
                captured["s5_exists_before_step"] = self._call_chain_dir(report_dir).exists()
                captured["s6_exists_before_step"] = run_step.final_report_path(report_dir).exists()
                return None

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step",
                    "auto",
                    "--project-dir",
                    str(project_dir),
                    "--report-dir",
                    str(report_dir),
                    "--response-json",
                    json.dumps(
                        {
                            "intent_patch": {
                                "action": "restart_from_step",
                                "restart_step_id": "step4",
                            }
                        },
                        ensure_ascii=False,
                    ),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step4": {"gate": "binary_generation"}}),
            ), patch.object(
                run_step,
                "execute_step",
                side_effect=fake_execute_step,
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)
            self.assertEqual(exit_code, 0)
            self.assertEqual(captured["step_id"], "step4")
            self.assertEqual(captured["run_context"]["base_branch"], "base")
            self.assertEqual(captured["run_context"]["current_branch"], "current")
            self.assertTrue(captured["s4_exists_before_step"])
            self.assertTrue(captured["s5_exists_before_step"])
            self.assertTrue(captured["s6_exists_before_step"])
            self.assertEqual(saved["state"]["current_step"], "step5")
            self.assertEqual(saved["state"]["completed_step"], "step4")
            self.assertEqual(saved["step5"]["input"]["base_branch"], "base")

    def test_step1_ref_preflight_persists_unique_remote_ref_and_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "artifact_inputs",
                "current_branch": "release-2.0.0",
                "current_source_project_dir": str(project_dir),
            }
            resolution = {
                "status": "resolved",
                "requested_ref": "release-2.0.0",
                "resolved_ref": "origin/release-2.0.0",
                "resolved_commit": "a" * 40,
                "resolution_mode": "unique_remote",
                "candidates": [
                    {"ref": "origin/release-2.0.0", "commit": "a" * 40, "kind": "remote", "score": 200},
                ],
                "fingerprint": "fingerprint-current",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=resolution):
                updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertIsNone(interaction)
        self.assertEqual(updated["current_branch"], "release-2.0.0")
        self.assertEqual(updated["current_requested_ref"], "release-2.0.0")
        self.assertEqual(updated["current_resolved_ref"], "origin/release-2.0.0")
        self.assertEqual(updated["current_resolved_commit"], "a" * 40)
        self.assertEqual(updated["current_ref_resolution_mode"], "unique_remote")
        self.assertEqual(updated["current_ref_candidate_count"], 1)
        self.assertEqual(
            updated["current_ref_binding"],
            {
                "schema": "java-upgrade-analyzer.remote-ref-binding.v1",
                "repo_dir": str(project_dir.resolve()),
                "requested_ref": "release-2.0.0",
                "remote": "",
                "canonical_ref": "",
                "expected_commit": "a" * 40,
                "artifact_path": "",
            },
        )

    def test_stale_remote_configuration_card_is_cleared_for_live_recheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report_dir)
            pending = {
                "step_id": "step1",
                "reason_code": "STEP1_REMOTE_CONFIGURATION_MISSING",
                "must_wait_for_user_reply": True,
            }
            state["state"].update({
                "current_step": "step1",
                "status": "awaiting_user_input",
                "pending_interaction": pending,
            })
            run_step.save_main_state(report_dir, state)
            run_step.save_interaction_file(report_dir, pending)

            cleared = run_step.clear_stale_git_interaction_for_recheck(
                state,
                report_dir,
                pending,
            )
            saved = run_step.load_main_state(report_dir)

        self.assertTrue(cleared)
        self.assertEqual(saved["state"]["status"], "ready")
        self.assertIsNone(saved["state"]["pending_interaction"])

    def test_step1_ref_preflight_discards_unbound_expected_commit_from_old_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "checkout_build",
                "base_branch": "release",
                "base_expected_commit": "a" * 40,
                "base_resolved_commit": "a" * 40,
                "base_requested_ref": "release",
            }
            resolution = {
                "status": "resolved",
                "requested_ref": "release",
                "resolved_ref": "origin/release",
                "resolved_commit": "b" * 40,
                "remote": "origin",
                "remote_ref": "refs/heads/release",
                "resolution_mode": "live_remote",
                "candidates": [{
                    "ref": "origin/release",
                    "commit": "b" * 40,
                    "remote": "origin",
                    "canonical_ref": "refs/heads/release",
                }],
            }

            with patch.object(
                run_step, "resolve_step1_ref", return_value=resolution
            ) as resolver:
                updated, interaction = run_step.resolve_step1_refs_for_execution(
                    context, project_dir
                )

        self.assertIsNone(interaction)
        self.assertEqual(resolver.call_args.kwargs["expected_commit"], "")
        self.assertEqual(updated["base_expected_commit"], "b" * 40)
        self.assertEqual(updated["base_resolved_commit"], "b" * 40)

    def test_step1_ref_preflight_reuses_expected_commit_only_with_matching_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "checkout_build",
                "base_branch": "release",
                "base_expected_commit": "a" * 40,
                "base_ref_binding": {
                    "schema": "java-upgrade-analyzer.remote-ref-binding.v1",
                    "repo_dir": str(project_dir.resolve()),
                    "requested_ref": "release",
                    "remote": "origin",
                    "canonical_ref": "refs/heads/release",
                    "expected_commit": "a" * 40,
                    "artifact_path": "",
                },
            }
            resolution = {
                "status": "resolved",
                "requested_ref": "release",
                "resolved_ref": "origin/release",
                "resolved_commit": "a" * 40,
                "remote": "origin",
                "remote_ref": "refs/heads/release",
                "resolution_mode": "live_remote_expected_commit",
                "candidates": [],
            }

            with patch.object(
                run_step, "resolve_step1_ref", return_value=resolution
            ) as resolver:
                updated, interaction = run_step.resolve_step1_refs_for_execution(
                    context, project_dir
                )

        self.assertIsNone(interaction)
        self.assertEqual(
            resolver.call_args.kwargs["expected_commit"],
            "a" * 40,
        )
        self.assertEqual(resolver.call_args.kwargs["expected_remote"], "origin")
        self.assertEqual(
            resolver.call_args.kwargs["expected_remote_ref"],
            "refs/heads/release",
        )
        self.assertEqual(updated["base_expected_commit"], "a" * 40)

    def test_step1_unmaterializable_pinned_commit_is_system_error_not_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "checkout_build",
                "base_branch": "release",
                "base_expected_commit": "a" * 40,
                "base_ref_binding": {
                    "schema": "java-upgrade-analyzer.remote-ref-binding.v1",
                    "repo_dir": str(project_dir.resolve()),
                    "requested_ref": "release",
                    "remote": "origin",
                    "canonical_ref": "refs/heads/release",
                    "expected_commit": "a" * 40,
                    "artifact_path": "",
                },
            }
            resolution = {
                "status": "fetch_failed",
                "source_status": "remote_expected_commit_unmaterializable",
                "expected_commit": "a" * 40,
                "observed_commit": "b" * 40,
            }

            with patch.object(
                run_step,
                "resolve_step1_ref",
                return_value=resolution,
            ), self.assertRaises(run_step.StepError) as raised:
                run_step.resolve_step1_refs_for_execution(
                    context,
                    project_dir,
                )

        self.assertIn("不会要求用户重新选择 ref", str(raised.exception))
        self.assertEqual(
            raised.exception.reason_codes,
            ["STEP1_REMOTE_EXPECTED_COMMIT_UNMATERIALIZABLE"],
        )

    def test_step1_persists_remote_binding_before_initial_materialization_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            commit = "a" * 40
            context = {
                "analysis_mode": "checkout_build",
                "base_branch": "release",
            }
            first_resolution = {
                "status": "fetch_failed",
                "source_status": "remote_expected_commit_unmaterializable",
                "expected_commit": commit,
                "queried_at": "2026-08-07T00:00:00Z",
                "fingerprint": "remote-selection",
                "candidates": [{
                    "remote": "origin",
                    "canonical_ref": "refs/heads/release",
                    "ref": "origin/release",
                    "commit": commit,
                }],
                "failures": [{
                    "remote": "origin",
                    "stage": "fetch_commit",
                    "reason": "temporary network failure",
                }],
            }
            snapshots = []
            with patch.object(
                run_step,
                "resolve_step1_ref",
                return_value=first_resolution,
            ), self.assertRaises(run_step.StepError):
                run_step.resolve_step1_refs_for_execution(
                    context,
                    project_dir,
                    on_side_resolved=lambda partial, _side, _resolution: snapshots.append(
                        json.loads(json.dumps(partial))
                    ),
                )

            self.assertEqual(len(snapshots), 1)
            persisted = snapshots[0]
            self.assertEqual(persisted["base_expected_commit"], commit)
            self.assertEqual(persisted["base_ref_binding"]["remote"], "origin")
            self.assertEqual(
                persisted["base_ref_binding"]["canonical_ref"],
                "refs/heads/release",
            )

            resolved = {
                "status": "resolved",
                "source_status": "remote_source_resolved",
                "requested_ref": "release",
                "resolved_ref": "origin/release",
                "resolved_commit": commit,
                "remote": "origin",
                "remote_ref": "refs/heads/release",
                "resolution_mode": "pinned_commit",
            }
            with patch.object(
                run_step,
                "resolve_step1_ref",
                return_value=resolved,
            ) as resolver:
                updated, interaction = run_step.resolve_step1_refs_for_execution(
                    persisted,
                    project_dir,
                )

        self.assertIsNone(interaction)
        self.assertEqual(updated["base_resolved_commit"], commit)
        self.assertEqual(resolver.call_args.kwargs["expected_commit"], commit)
        self.assertEqual(resolver.call_args.kwargs["expected_remote"], "origin")
        self.assertEqual(
            resolver.call_args.kwargs["expected_remote_ref"],
            "refs/heads/release",
        )

    def test_step1_remote_operation_failure_is_system_error_not_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "analysis_mode": "checkout_build",
                "base_branch": "release",
            }
            resolution = {
                "status": "fetch_failed",
                "source_status": "remote_query_failed",
                "repository_path": str(project_dir),
                "failures": [{
                    "remote": "origin",
                    "stage": "targeted_ls_remote",
                    "reason": "ssh handshake timed out",
                    "reason_code": "transient_network_failure",
                    "attempts": [{"attempt": 1}, {"attempt": 2}, {"attempt": 3}],
                }],
            }

            with patch.object(
                run_step,
                "resolve_step1_ref",
                return_value=resolution,
            ), self.assertRaises(run_step.StepError) as raised:
                run_step.resolve_step1_refs_for_execution(
                    context,
                    project_dir,
                )

        self.assertIn("ssh handshake timed out", str(raised.exception))
        self.assertEqual(
            raised.exception.reason_codes,
            ["STEP1_REMOTE_OPERATION_FAILED"],
        )

    def test_step1_publishes_base_snapshot_before_current_remote_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            base_resolution = {
                "status": "resolved",
                "source_status": "remote_source_resolved",
                "requested_ref": "base",
                "resolved_ref": "origin/base",
                "resolved_commit": "a" * 40,
                "remote": "origin",
                "remote_ref": "refs/heads/base",
                "resolution_mode": "live_remote",
                "candidates": [],
            }
            current_failure = {
                "status": "fetch_failed",
                "source_status": "remote_query_failed",
                "failures": [{"reason": "temporary TLS failure"}],
            }
            snapshots = []

            with patch.object(
                run_step,
                "resolve_step1_ref",
                side_effect=[base_resolution, current_failure],
            ), self.assertRaises(run_step.StepError):
                run_step.resolve_step1_refs_for_execution(
                    {
                        "base_branch": "base",
                        "current_branch": "current",
                    },
                    project_dir,
                    on_side_resolved=lambda context, side, resolution: snapshots.append(
                        (side, context, resolution)
                    ),
                )

        self.assertEqual([item[0] for item in snapshots], ["base", "current"])
        self.assertEqual(snapshots[-1][1]["base_resolved_commit"], "a" * 40)

    def test_main_persists_partial_ref_snapshot_when_second_side_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp) / "project"
            report_dir = project_dir / ".upgrade-report"
            project_dir.mkdir()
            report_dir.mkdir()
            context = {
                "project_dir": str(project_dir),
                "report_dir": str(report_dir),
                "analysis_mode": "checkout_build",
                "base_branch": "base",
                "current_branch": "current",
                "target_module": ".",
            }

            def fail_after_base(
                run_context,
                _project,
                *,
                on_side_resolved,
                **_kwargs,
            ):
                partial = dict(run_context)
                partial["base_resolved_commit"] = "a" * 40
                partial["base_expected_commit"] = "a" * 40
                on_side_resolved(partial, "base", {"status": "resolved"})
                raise run_step.StepError(
                    "current remote failed",
                    reason_codes=["STEP1_REMOTE_OPERATION_FAILED"],
                )

            with patch.object(
                sys,
                "argv",
                [
                    "run_step.py",
                    "--step", "step0",
                    "--project-dir", str(project_dir),
                    "--report-dir", str(report_dir),
                ],
            ), patch.object(
                run_step,
                "load_manifest",
                return_value=({}, {"step0": {"gate": None}}),
            ), patch.object(
                run_step,
                "build_run_context",
                return_value=context,
            ), patch.object(
                run_step,
                "resolve_step1_refs_for_execution",
                side_effect=fail_after_base,
            ):
                exit_code = run_step.main()

            saved = run_step.load_main_state(report_dir)

        self.assertEqual(exit_code, 1)
        self.assertEqual(
            saved["step0"]["input"]["base_resolved_commit"],
            "a" * 40,
        )
        self.assertEqual(saved["state"]["status"], "blocked_by_system")

    def test_step1_input_change_invalidates_bound_ref_snapshot(self):
        project_dir = Path("/project")
        old_context = {
            "analysis_mode": "artifact_inputs",
            "base_artifact_path": "/artifacts/old-base.jar",
            "base_source_project_dir": "/repos/old",
            "base_branch": "release",
            "base_expected_commit": "a" * 40,
            "base_resolved_commit": "a" * 40,
            "base_requested_ref": "release",
            "base_ref_binding": {
                "schema": "java-upgrade-analyzer.remote-ref-binding.v1",
                "repo_dir": "/repos/old",
                "requested_ref": "release",
                "remote": "origin",
                "canonical_ref": "refs/heads/release",
                "expected_commit": "a" * 40,
                "artifact_path": "/artifacts/old-base.jar",
            },
        }

        updated = run_step.merge_user_response_into_run_context(
            old_context,
            {
                "base_artifact_path": "/artifacts/new-base.jar",
                "base_source_project_dir": "/repos/new",
            },
            project_dir,
        )

        self.assertNotIn("base_expected_commit", updated)
        self.assertNotIn("base_resolved_commit", updated)
        self.assertNotIn("base_requested_ref", updated)
        self.assertNotIn("base_ref_binding", updated)

    def test_explicit_cli_branch_overrides_restored_suffix_branch_and_ref_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            report_dir = project_dir / ".upgrade-report"
            args = self._make_default_args(project_dir, report_dir)
            args.current_branch = "release"
            old_context = {
                "current_branch": "release.DEV",
                "current_branch_explicit": True,
                "current_requested_ref": "release.DEV",
                "current_resolved_ref": "origin/release.DEV",
                "current_resolved_commit": "d" * 40,
                "current_expected_commit": "d" * 40,
                "current_ref_remote": "origin",
                "current_ref_remote_ref": "refs/heads/release.DEV",
                "current_ref_binding": {
                    "schema": "java-upgrade-analyzer.remote-ref-binding.v1",
                    "repo_dir": str(project_dir.resolve()),
                    "requested_ref": "release.DEV",
                    "remote": "origin",
                    "canonical_ref": "refs/heads/release.DEV",
                    "expected_commit": "d" * 40,
                    "artifact_path": "",
                },
                "pinned_source_snapshot": {
                    "schema": "java-upgrade-analyzer.pinned-source-snapshot.v1",
                    "commit": "d" * 40,
                },
            }

            context = run_step.build_run_context(
                args,
                old_context,
                {},
                allow_external_seed=True,
            )

        self.assertEqual(context["current_branch"], "release")
        self.assertTrue(context["current_branch_explicit"])
        for stale_field in (
            "current_requested_ref",
            "current_resolved_ref",
            "current_resolved_commit",
            "current_expected_commit",
            "current_ref_remote",
            "current_ref_remote_ref",
            "current_ref_binding",
            "pinned_source_snapshot",
        ):
            self.assertNotIn(stale_field, context)

    def test_step1_ref_preflight_resolves_both_branches_from_project_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "origin.git"
            project_dir = root / "project"

            def git(cwd, *args):
                completed = subprocess.run(
                    ["git", *args],
                    cwd=cwd,
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                )
                return completed.stdout.strip()

            git(root, "init", "--bare", str(remote))
            git(root, "clone", str(remote), str(project_dir))
            git(project_dir, "config", "user.email", "step1@example.invalid")
            git(project_dir, "config", "user.name", "Step1 Test")
            git(project_dir, "commit", "--allow-empty", "-m", "base")
            base_commit = git(project_dir, "rev-parse", "HEAD")
            git(project_dir, "branch", "nbs-base", base_commit)
            git(project_dir, "commit", "--allow-empty", "-m", "current")
            current_commit = git(project_dir, "rev-parse", "HEAD")
            git(
                project_dir,
                "branch",
                "nbs-mid26.07.22.DEV",
                current_commit,
            )
            git(
                project_dir,
                "push",
                "origin",
                "nbs-base",
                "nbs-mid26.07.22.DEV",
            )

            updated, interaction = run_step.resolve_step1_refs_for_execution(
                {
                    "analysis_mode": "checkout_build",
                    "base_branch": "nbs-base",
                    "current_branch": "nbs-mid26.07.22.DEV",
                },
                project_dir,
            )

        self.assertIsNone(interaction)
        self.assertEqual(updated["base_resolved_commit"], base_commit)
        self.assertEqual(updated["current_resolved_commit"], current_commit)
        self.assertEqual(updated["base_ref_remote"], "origin")
        self.assertEqual(updated["current_ref_remote"], "origin")

    def test_step1_direct_artifacts_pin_explicit_refs_before_coordinate_fallback(self):
        context = {
            "analysis_mode": "artifact_inputs",
            "base_artifact_path": "/tmp/base.jar",
            "current_artifact_path": "/tmp/current.jar",
            "base_branch": "possibly-ambiguous-base",
            "current_branch": "possibly-ambiguous-current",
        }

        resolution = {
            "status": "resolved",
            "source_status": "remote_source_resolved",
            "requested_ref": "release",
            "resolved_ref": "origin/release",
            "resolved_commit": "c" * 40,
            "remote": "origin",
            "remote_ref": "refs/heads/release",
            "resolution_mode": "live_remote",
            "candidates": [],
        }
        with patch.object(
            run_step, "resolve_step1_ref", return_value=resolution,
        ) as resolver:
            updated, interaction = run_step.resolve_step1_refs_for_execution(
                context, "/tmp/project"
            )

        self.assertIsNone(interaction)
        self.assertEqual(updated["base_resolved_commit"], "c" * 40)
        self.assertEqual(updated["current_resolved_commit"], "c" * 40)
        self.assertEqual(resolver.call_count, 2)

    def test_step1_ref_preflight_stops_for_ambiguous_remote_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {"current_branch": "release-2.0.0"}
            resolution = {
                "status": "ambiguous",
                "requested_ref": "release-2.0.0",
                "resolved_ref": "",
                "resolved_commit": "",
                "resolution_mode": "unresolved",
                "candidates": [
                    {"ref": "origin/release-2.0.0", "commit": "a" * 40, "kind": "remote", "score": 200},
                    {"ref": "upstream/release-2.0.0", "commit": "b" * 40, "kind": "remote", "score": 200},
                ],
                "fingerprint": "ambiguous-current",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=resolution):
                _updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertEqual(interaction["reason_code"], "ambiguous_step1_source_ref")
        self.assertEqual(interaction["kind"], "input_request")
        self.assertEqual(interaction["required_fields"], ["current_branch"])
        self.assertEqual(len(interaction["ref_resolution_requests"][0]["candidates"]), 2)
        self.assertTrue(interaction["must_wait_for_user_reply"])

    def test_step1_remote_failure_offers_explicit_local_fallback_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {"current_branch": "release-2.0.0"}
            resolution = {
                "status": "not_found",
                "source_status": "awaiting_local_source_confirmation",
                "requested_ref": "release-2.0.0",
                "resolved_ref": "",
                "resolved_commit": "",
                "resolution_mode": "unresolved",
                "candidates": [],
                "failures": [{"remote": "origin", "stage": "ls_remote", "reason": "network unavailable"}],
                "local_candidate_commit": "d" * 40,
                "dirty": False,
                "fingerprint": "remote-unavailable-current",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=resolution):
                _updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertEqual(interaction["reason_code"], "step1_remote_source_unavailable")
        self.assertIn("current_allow_local_source", interaction["response_schema"]["properties"])
        self.assertIn("confirm_local_source", {row["id"] for row in interaction["options"]})
        request = interaction["ref_resolution_requests"][0]
        self.assertEqual(request["local_candidate_commit"], "d" * 40)
        self.assertEqual(request["remote_failures"][0]["stage"], "ls_remote")

    def test_step1_passes_confirmed_local_fallback_flags_to_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {
                "current_branch": "release-2.0.0",
                "current_ref_binding": {},
                "current_allow_local_source": True,
                "current_allow_dirty_local_source": True,
            }
            resolution = {
                "status": "resolved",
                "source_status": "user_confirmed_local_source",
                "requested_ref": "release-2.0.0",
                "resolved_ref": "release-2.0.0",
                "resolved_commit": "e" * 40,
                "resolution_mode": "user_confirmed_local_source",
                "candidates": [],
                "fingerprint": "confirmed-local-current",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=resolution) as resolver:
                updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertIsNone(interaction)
        self.assertEqual(updated["current_ref_source_status"], "user_confirmed_local_source")
        self.assertTrue(resolver.call_args.kwargs["allow_local_source"])
        self.assertTrue(resolver.call_args.kwargs["allow_dirty_local_source"])

    def test_step1_source_only_input_requires_revision_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            project_dir = Path(tmp)
            context = {"base_source_project_dir": str(project_dir)}
            head_resolution = {
                "status": "resolved",
                "requested_ref": "HEAD",
                "resolved_ref": "HEAD",
                "resolved_commit": "c" * 40,
                "resolution_mode": "exact",
                "candidates": [],
                "fingerprint": "source-head",
            }

            with patch.object(run_step, "resolve_step1_ref", return_value=head_resolution):
                _updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)

        self.assertEqual(
            interaction["reason_code"],
            "step1_source_revision_confirmation_required",
        )
        self.assertEqual(interaction["required_fields"], ["base_branch"])
        request = interaction["ref_resolution_requests"][0]
        self.assertEqual(request["detected_commit"], "c" * 40)
        self.assertEqual(request["source_project_dir"], str(project_dir.resolve()))

    def test_step1_ref_confirmation_rejects_same_unresolved_value(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "ambiguous_step1_source_ref",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "action_requirements": {
                "continue": {"required_fields": ["current_branch"]},
            },
            "ref_resolution_requests": [
                {
                    "field": "current_branch",
                    "requested_ref": "release-2.0.0",
                }
            ],
        }

        with self.assertRaisesRegex(run_step.StepError, "不同的明确 ref"):
            run_step.validate_pending_interaction_response(
                interaction,
                {"action": "continue", "current_branch": "release-2.0.0"},
            )

    def test_step1_ref_confirmation_accepts_same_ref_when_repository_changes(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "step1_remote_source_unavailable",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "action_requirements": {
                "continue": {"required_fields": ["current_branch"]},
            },
            "response_schema": {
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "current_branch": {"type": "string"},
                    "current_source_project_dir": {"type": "string"},
                },
            },
            "ref_resolution_requests": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                    "source_project_dir": "/stale/repository",
                }
            ],
        }

        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "continue",
                "current_branch": "nbs-mid26.07.22.DEV",
                "current_source_project_dir": "/actual/repository",
            },
        )

    def test_step1_ref_confirmation_accepts_explicit_remote_requery(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "step1_remote_source_unavailable",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "action_requirements": {
                "continue": {"required_fields": ["current_branch"]},
            },
            "response_schema": {
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "current_branch": {"type": "string"},
                    "retry_remote_fetch": {"type": "boolean"},
                },
            },
            "ref_resolution_requests": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "status": "not_found",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                    "source_project_dir": "/actual/repository",
                    "remote_failures": [
                        {
                            "stage": "resolve",
                            "reason": "repository has no configured remote",
                        }
                    ],
                }
            ],
        }

        run_step.validate_pending_interaction_response(
            interaction,
            {
                "action": "continue",
                "retry_remote_fetch": True,
            },
        )

    def test_step1_ref_protocol_exposes_actual_repository_correction_field(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "step1_remote_source_unavailable",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "response_schema": {
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "current_branch": {"type": "string"},
                },
            },
            "ref_resolution_requests": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                    "source_project_dir": "/actual/repository",
                }
            ],
        }

        enhanced = run_step.apply_interaction_protocol_enhancements(
            interaction,
            "step1",
        )

        self.assertIn(
            "current_source_project_dir",
            enhanced["response_schema"]["properties"],
        )

    def test_step1_old_artifact_ref_card_clarifies_other_side_was_not_queried(self):
        interaction = {
            "step_id": "step1",
            "reason_code": "step1_remote_source_unavailable",
            "question": "请确认当前侧 ref。",
            "options": [{"id": "continue"}],
            "required_fields": ["current_branch"],
            "response_schema": {
                "required": ["action"],
                "properties": {
                    "action": {"type": "string"},
                    "current_branch": {"type": "string"},
                },
            },
            "ref_resolution_requests": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                    "source_project_dir": "/actual/repository",
                    "artifact_path": "/tmp/current.jar",
                }
            ],
            "source_ref_decision_items": [
                {
                    "side": "current",
                    "field": "current_branch",
                    "requested_ref": "nbs-mid26.07.22.DEV",
                }
            ],
        }

        enhanced = run_step.apply_interaction_protocol_enhancements(
            interaction,
            "step1",
        )

        self.assertEqual(
            enhanced["ref_resolution_scope"]["queried_sides"],
            ["current"],
        )
        self.assertEqual(
            enhanced["ref_resolution_scope"]["not_evaluated_sides"],
            ["base"],
        )
        self.assertIn("不表示基准侧执行过远端查询", enhanced["question"])
        self.assertEqual(
            enhanced["source_ref_decision_items"][0]["source_project_dir"],
            "/actual/repository",
        )

    def test_step4_startup_target_hint_preserves_explicit_rerun_intent(self):
        state = run_step.new_main_state(Path.cwd() / ".upgrade-report-test")
        state["state"].update({
            "current_step": "step5",
            "completed_step": "step4",
            "pending_interaction": {
                "step_id": "step4",
                "options": [{"id": "rerun_current_step"}],
            },
        })
        args = SimpleNamespace(step="auto")

        self.assertEqual(
            run_step._startup_step4_recovery_target_hint(
                args,
                state,
                {"action": "rerun_current_step"},
            ),
            "step4",
        )
        self.assertEqual(
            run_step._startup_step4_recovery_target_hint(
                args,
                state,
                {
                    "action": "restart_from_step",
                    "restart_step_id": "step2",
                },
            ),
            "step2",
        )

    def test_step4_recovery_disposition_classifier_is_fail_closed(self):
        report = Path.cwd() / ".upgrade-report-test"
        cases = (
            (
                "no_bound_transaction",
                run_step._STEP4_RELEASE_FATAL,
                None,
            ),
            (
                "rolled_back_interrupted_transaction",
                run_step._STEP4_RELEASE_RESUME_PIPELINE,
                None,
            ),
            (
                "committed_receipt_requires_republication",
                run_step._STEP4_RELEASE_REPUBLISH,
                True,
            ),
            (
                "unexpected-new-disposition",
                run_step._STEP4_RELEASE_FATAL,
                None,
            ),
        )
        for disposition, expected, reusable in cases:
            with self.subTest(disposition=disposition):
                manager = (
                    patch.object(
                        run_step,
                        "_validated_active_generation_is_current",
                        return_value=reusable,
                    )
                    if reusable is not None
                    else nullcontext()
                )
                with manager:
                    decision = run_step._classify_step4_recovery_disposition(
                        report,
                        disposition,
                        expected_gate_name="jar_compare",
                        expected_strict_risk_gate=False,
                    )
                self.assertEqual(decision["action"], expected)

        receipt = {
            "committed_receipt_identity": "a" * 64,
            "binding": {"result_generation_identity": "b" * 64},
        }
        with patch.object(
            run_step,
            "verify_current_step4_release",
            return_value=receipt,
        ):
            decision = run_step._classify_step4_recovery_disposition(
                report,
                "nothing_to_recover",
                expected_gate_name="jar_compare",
                expected_strict_risk_gate=False,
            )
        self.assertEqual(decision["action"], run_step._STEP4_RELEASE_CURRENT)
        self.assertTrue(decision["release_verified"])

        for reusable, expected in (
            (True, run_step._STEP4_RELEASE_REPUBLISH),
            (False, run_step._STEP4_RELEASE_RESUME_PIPELINE),
        ):
            with (
                self.subTest(reusable=reusable),
                patch.object(
                    run_step,
                    "verify_current_step4_release",
                    side_effect=binary_report.BinaryReportError(
                        "TEST_RELEASE_INVALID", "fixture"
                    ),
                ),
                patch.object(
                    run_step,
                    "_validated_active_generation_is_current",
                    return_value=reusable,
                ),
            ):
                decision = run_step._classify_step4_recovery_disposition(
                    report,
                    "nothing_to_recover",
                    expected_gate_name="jar_compare",
                    expected_strict_risk_gate=False,
                )
            self.assertEqual(decision["action"], expected)

    def test_step4_republication_marker_invalidates_done_before_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report)
            state["state"].update({
                "current_step": "done",
                "completed_step": "step6",
                "status": "completed",
            })
            state["step4"]["output"] = {
                "step0_confirmed": True,
                "source_dirs": [str(Path(tmp) / "src")],
            }
            state["step5"]["input"] = {
                "step5_scope_mode": "full",
            }
            generation = "a" * 64
            with patch.object(
                run_step,
                "_read_step4_active_descriptor",
                return_value={"result_generation_identity": generation},
            ):
                marker = run_step._begin_step4_report_republication_state(
                    main_state=state,
                    report_dir=report,
                )

            persisted = run_step.load_main_state(report)
            self.assertEqual(persisted["state"]["current_step"], "step5")
            self.assertEqual(persisted["state"]["completed_step"], "step4")
            self.assertIsNone(persisted["state"]["pending_interaction"])
            self.assertEqual(
                persisted["state"][
                    "step4_report_republication_pending"
                ]["marker_identity"],
                marker["marker_identity"],
            )

            with patch.object(
                run_step,
                "build_interaction_payload",
                return_value=None,
            ):
                interaction = (
                    run_step._reconcile_main_state_after_step4_republication(
                        main_state=persisted,
                        report_dir=report,
                        project_dir=Path(tmp),
                        manifest_steps={"step4": {}},
                        verified_release={
                            "binding": {
                                "result_generation_identity": generation
                            }
                        },
                    )
                )
            finalized = run_step.load_main_state(report)

        self.assertIsNone(interaction)
        self.assertNotIn(
            "step4_report_republication_pending", finalized["state"]
        )
        self.assertEqual(finalized["state"]["current_step"], "step5")

    def test_step4_republication_orders_durable_invalidation_before_publish(self):
        state = run_step.new_main_state(Path.cwd() / ".upgrade-report-test")
        state["state"].update({
            "current_step": "done",
            "completed_step": "step6",
        })
        state["step4"]["output"] = {"step0_confirmed": True}
        marker = {
            "schema": run_step._STEP4_REPORT_REPUBLICATION_MARKER_SCHEMA,
            "result_generation_identity": "a" * 64,
            "refresh_scope_interaction": False,
            "marker_identity": "b" * 64,
        }
        verified = {
            "binding": {"result_generation_identity": "a" * 64},
            "committed_receipt_identity": "c" * 64,
        }
        events = []

        with (
            patch.object(
                run_step,
                "_workflow_has_reached_step4",
                return_value=True,
            ),
            patch.object(
                run_step,
                "_begin_step4_report_republication_state",
                side_effect=lambda **_kwargs: (
                    events.append("invalidate") or marker
                ),
            ),
            patch.object(
                run_step,
                "_republish_current_binary_step4_reports",
                side_effect=lambda **_kwargs: (
                    events.append("publish") or verified
                ),
            ),
            patch.object(
                run_step,
                "_reconcile_main_state_after_step4_republication",
                side_effect=lambda **_kwargs: events.append("reconcile"),
            ),
        ):
            result = run_step._apply_step4_startup_recovery(
                decision={"action": run_step._STEP4_RELEASE_REPUBLISH},
                target_step_id="done",
                args=SimpleNamespace(step="auto"),
                main_state=state,
                report_dir=Path.cwd() / ".upgrade-report-test",
                project_dir=Path.cwd(),
                manifest_steps={"step4": {}},
                gate_name="jar_compare",
                strict_risk_gate=False,
                has_structured_response=False,
            )

        self.assertEqual(events, ["invalidate", "publish", "reconcile"])
        self.assertTrue(result["applied"])
        self.assertEqual(result["forced_step_id"], "step5")

    def test_explicit_step4_clears_old_pending_card_and_runs_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report)
            state["state"].update({
                "current_step": "step5",
                "completed_step": "step4",
                "pending_interaction": {"step_id": "step4"},
            })
            state["step4"]["input"] = {"step0_confirmed": True}

            result = run_step._apply_step4_startup_recovery(
                decision={"action": run_step._STEP4_RELEASE_CURRENT},
                target_step_id="step4",
                args=SimpleNamespace(step="step4"),
                main_state=state,
                report_dir=report,
                project_dir=Path(tmp),
                manifest_steps={"step4": {}},
                gate_name="jar_compare",
                strict_risk_gate=False,
                has_structured_response=True,
            )

        self.assertTrue(result["explicit_pipeline"])
        self.assertEqual(result["forced_step_id"], "step4")
        self.assertTrue(result["discard_structured_response"])
        self.assertIsNone(state["state"]["pending_interaction"])
        self.assertEqual(state["state"]["current_step"], "step4")

    def test_step4_renderer_failure_rolls_back_child_transaction_without_result(self):
        transaction_id = "a" * 32
        binding = {"report_implementation_identity": "b" * 64}
        metadata = {
            "state": "pending_gate",
            "transaction_id": transaction_id,
            "binding": binding,
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(
                run_step,
                "report_publication_transaction_recovery_metadata",
                side_effect=[{"state": "absent"}, metadata],
            ),
            patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                side_effect=run_step.StepError("renderer failed"),
            ),
            patch.object(
                run_step,
                "rollback_report_publication",
                return_value=True,
            ) as rollback,
        ):
            with self.assertRaises(run_step.StepError) as caught:
                run_step._republish_current_binary_step4_reports(
                    report_dir=Path(tmp) / ".upgrade-report",
                    project_dir=Path(tmp),
                    gate_name="jar_compare",
                    strict_risk_gate=False,
                )

        rollback.assert_called_once_with(
            run_step._step4_report_publication_destinations(
                Path(tmp) / ".upgrade-report"
            ),
            expected_transaction_id=transaction_id,
            expected_binding=binding,
        )
        self.assertEqual(
            caught.exception.diagnostic["report_publication_rollback"],
            "restored_previous_reports",
        )

    def test_step4_republication_timing_failure_does_not_reverse_commit(self):
        generation = "1" * 64
        validation = "2" * 64
        validation_sha256 = "3" * 64
        implementation = "4" * 64
        content_identity = "5" * 64
        committed_identity = "6" * 64
        binding = {
            "result_generation_identity": generation,
            "validation_run_identity": validation,
            "validation_result_sha256": validation_sha256,
            "report_implementation_identity": implementation,
        }
        transaction = {
            "transaction_id": "a" * 32,
            "binding": binding,
            "published_content_identity": content_identity,
        }
        rendered = {
            "phase": "step4",
            "publication_transaction": transaction,
        }
        receipt = {
            **transaction,
            "state": "pending_gate",
        }
        verified = {
            "binding": binding,
            "committed_receipt_identity": committed_identity,
        }
        release = {
            "step4": {"status": "current"},
            "step5": {"status": "stale"},
            "step6": {"status": "stale"},
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(
                run_step,
                "report_publication_transaction_recovery_metadata",
                return_value={"state": "absent"},
            ),
            patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                return_value=rendered,
            ),
            patch.object(
                run_step,
                "report_publication_transaction_receipt",
                return_value=receipt,
            ),
            patch.object(
                run_step,
                "read_active_binary_generation",
                return_value={
                    "result_generation_identity": generation,
                    "validation_run_identity": validation,
                    "validation_result_sha256": validation_sha256,
                },
            ),
            patch.object(
                run_step,
                "report_implementation_identity",
                return_value=implementation,
            ),
            patch.object(run_step, "run_gate", return_value=None),
            patch.object(
                run_step,
                "mark_report_publication_gate_passed",
                return_value={"gate": "passed"},
            ),
            patch.object(
                run_step,
                "publish_report_publication",
                return_value=True,
            ),
            patch.object(
                run_step,
                "commit_report_publication",
                return_value=True,
            ),
            patch.object(
                run_step,
                "reconcile_current_release",
                return_value=release,
            ),
            patch.object(
                run_step,
                "verify_current_step4_release",
                return_value=verified,
            ),
            patch.object(
                run_step,
                "write_csv_rows",
                side_effect=OSError("metrics unavailable"),
            ),
        ):
            result = run_step._republish_current_binary_step4_reports(
                report_dir=Path(tmp) / ".upgrade-report",
                project_dir=Path(tmp),
                gate_name="jar_compare",
                strict_risk_gate=False,
            )

        self.assertEqual(result, verified)

    def test_step4_republication_rejects_generation_switch_after_gate(self):
        old_generation = "1" * 64
        old_validation = "2" * 64
        old_validation_sha = "3" * 64
        new_generation = "7" * 64
        new_validation = "8" * 64
        new_validation_sha = "9" * 64
        implementation = "4" * 64
        binding = {
            "result_generation_identity": old_generation,
            "validation_run_identity": old_validation,
            "validation_result_sha256": old_validation_sha,
            "report_implementation_identity": implementation,
        }
        transaction = {
            "transaction_id": "a" * 32,
            "binding": binding,
            "published_content_identity": "5" * 64,
        }
        receipt = {**transaction, "state": "pending_gate"}
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(
                run_step,
                "report_publication_transaction_recovery_metadata",
                side_effect=[
                    {"state": "absent"},
                    {
                        "state": "pending_gate",
                        "transaction_id": transaction["transaction_id"],
                        "binding": binding,
                    },
                ],
            ),
            patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                return_value={
                    "phase": "step4",
                    "publication_transaction": transaction,
                },
            ),
            patch.object(
                run_step,
                "report_publication_transaction_receipt",
                return_value=receipt,
            ),
            patch.object(
                run_step,
                "read_active_binary_generation",
                side_effect=[
                    {
                        "result_generation_identity": old_generation,
                        "validation_run_identity": old_validation,
                        "validation_result_sha256": old_validation_sha,
                    },
                    {
                        "result_generation_identity": new_generation,
                        "validation_run_identity": new_validation,
                        "validation_result_sha256": new_validation_sha,
                    },
                ],
            ),
            patch.object(
                run_step,
                "report_implementation_identity",
                return_value=implementation,
            ),
            patch.object(run_step, "run_gate", return_value=None),
            patch.object(
                run_step, "mark_report_publication_gate_passed"
            ) as mark_gate,
            patch.object(
                run_step,
                "rollback_report_publication",
                return_value=True,
            ) as rollback,
        ):
            with self.assertRaises(run_step.StepError) as caught:
                run_step._republish_current_binary_step4_reports(
                    report_dir=Path(tmp) / ".upgrade-report",
                    project_dir=Path(tmp),
                    gate_name="binary_generation",
                    strict_risk_gate=False,
                )

        self.assertIn(
            "BINARY_STEP4_REPORT_TRANSACTION_BINDING_MISMATCH",
            caught.exception.reason_codes,
        )
        mark_gate.assert_not_called()
        rollback.assert_called_once()

    def test_startup_recovery_failure_persists_blocked_step4_before_return(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            report = Path(tmp) / ".upgrade-report"
            project.mkdir()
            state = run_step.new_main_state(report)
            state["state"].update({
                "current_step": "done",
                "completed_step": "step6",
                "status": "completed",
            })
            run_step.save_main_state(report, state)
            failure = run_step.StepError(
                "corrupt recovery",
                reason_codes=["BINARY_STEP4_TRANSACTION_RECOVERY_FAILED"],
            )
            with (
                patch.object(
                    run_step,
                    "recover_worktrees_before_execution",
                    return_value={"removed_count": 0},
                ),
                patch.object(
                    run_step,
                    "load_manifest",
                    return_value=({}, {"step4": {"gate": "jar_compare"}}),
                ),
                patch.object(
                    run_step,
                    "_recover_and_apply_step4_startup_state",
                    side_effect=failure,
                ),
            ):
                exit_code = run_step.main(
                    [
                        "--step", "auto",
                        "--project-dir", str(project),
                        "--report-dir", str(report),
                    ],
                    _skip_environment_contract=True,
                )
            persisted = run_step.load_main_state(report)

        self.assertEqual(exit_code, 1)
        self.assertEqual(persisted["state"]["current_step"], "step4")
        self.assertEqual(persisted["state"]["status"], "blocked_by_system")
        self.assertIn(
            "BINARY_STEP4_TRANSACTION_RECOVERY_FAILED",
            persisted["state"]["blocking_reason_codes"],
        )

    def test_downstream_publication_gates_candidate_before_commit(self):
        transaction = {
            "transaction_id": "a" * 32,
            "binding": {
                "result_generation_identity": "b" * 64,
                "report_implementation_identity": "c" * 64,
            },
            "published_content_identity": "d" * 64,
            "destinations": ["one", "two", "three"],
            "candidate_destinations": ["s1", "s2", "s3"],
        }
        receipt = {**transaction, "state": "pending_gate"}
        release = {
            "step4": {"status": "current"},
            "step5": {"status": "current"},
            "step6": {"status": "stale"},
        }
        events = []

        def prepare_report(**kwargs):
            events.append("render")
            self.assertEqual(kwargs["phase"], "step5")
            return {
                "phase": "step5",
                "publication_transaction": transaction,
            }

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(
                run_step,
                "report_publication_transaction_recovery_metadata",
                return_value={"state": "absent"},
            ),
            patch.object(run_step, "require_current_release_stage"),
            patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                side_effect=prepare_report,
            ),
            patch.object(
                run_step,
                "report_publication_transaction_receipt",
                return_value=receipt,
            ),
            patch.object(
                run_step,
                "run_gate",
                side_effect=lambda *_args, **_kwargs: events.append("gate"),
            ) as gate,
            patch.object(
                run_step,
                "complete_downstream_report_publication_after_gate",
                side_effect=lambda *_args, **_kwargs: (
                    events.append("commit")
                    or {
                        "publication_receipt": {
                            "committed_receipt_identity": "e" * 64
                        },
                        "global_release": release,
                    }
                ),
            ) as complete,
        ):
            result = run_step._run_downstream_report_publication(
                stage="step5",
                report_dir=Path(tmp) / ".upgrade-report",
                project_dir=Path(tmp),
                gate_name="binary_report",
                strict_risk_gate=True,
                output_dir=(
                    Path(tmp) / ".upgrade-report" / "evidence" / "call_chain"
                ),
            )

        self.assertEqual(events, ["render", "gate", "commit"])
        self.assertIsNone(result["publication_transaction"])
        gate.assert_called_once()
        self.assertEqual(
            gate.call_args.kwargs["publication_transaction"], receipt
        )
        complete.assert_called_once_with(
            (Path(tmp) / ".upgrade-report").resolve(),
            "step5",
            expected_transaction_id="a" * 32,
            expected_binding=transaction["binding"],
            gate_name="binary_report",
            strict_risk_gate=True,
            workflow_lock_held=True,
        )

    def test_downstream_candidate_gate_failure_restores_previous_reports(self):
        transaction = {
            "transaction_id": "a" * 32,
            "binding": {"report_implementation_identity": "b" * 64},
            "published_content_identity": "c" * 64,
            "destinations": ["one", "two"],
            "candidate_destinations": ["s1", "s2"],
        }
        receipt = {**transaction, "state": "pending_gate"}
        metadata = {
            "state": "pending_gate",
            "transaction_id": transaction["transaction_id"],
            "binding": transaction["binding"],
        }

        def prepare_report(**kwargs):
            self.assertEqual(kwargs["phase"], "step6")
            return {
                "phase": "step6",
                "publication_transaction": transaction,
            }

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(
                run_step,
                "report_publication_transaction_recovery_metadata",
                side_effect=[{"state": "absent"}, metadata],
            ),
            patch.object(run_step, "require_current_release_stage"),
            patch.object(
                run_step,
                "_prepare_binary_report_publication_candidate_in_process",
                side_effect=prepare_report,
            ),
            patch.object(
                run_step,
                "report_publication_transaction_receipt",
                return_value=receipt,
            ),
            patch.object(
                run_step,
                "run_gate",
                side_effect=run_step.StepError("candidate rejected"),
            ),
            patch.object(
                run_step,
                "rollback_report_publication",
                return_value=True,
            ) as rollback,
            patch.object(
                run_step,
                "complete_downstream_report_publication_after_gate",
            ) as complete,
        ):
            with self.assertRaises(run_step.StepError) as caught:
                run_step._run_downstream_report_publication(
                    stage="step6",
                    report_dir=Path(tmp) / ".upgrade-report",
                    project_dir=Path(tmp),
                    gate_name="binary_final_report",
                    strict_risk_gate=False,
                    output_findings=(
                        Path(tmp) / ".upgrade-report" / ".runtime"
                        / "findings" / "s6_findings.json"
                    ),
                    output_report=(
                        Path(tmp) / ".upgrade-report" / "deliverables"
                        / "report.md"
                    ),
                )

        complete.assert_not_called()
        rollback.assert_called_once_with(
            run_step._downstream_report_publication_destinations(
                Path(tmp) / ".upgrade-report", "step6"
            ),
            expected_transaction_id=transaction["transaction_id"],
            expected_binding=transaction["binding"],
        )
        self.assertEqual(
            caught.exception.diagnostic["report_publication_rollback"],
            "restored_previous_reports",
        )

    def test_release_prerequisites_allow_target_stage_to_be_stale(self):
        release = {
            "step4": {"status": "current"},
            "step5": {"status": "current"},
            "step6": {"status": "stale"},
        }
        self.assertEqual(
            run_step._release_prerequisite_repair_step(
                release, "step6"
            ),
            "",
        )
        self.assertEqual(
            run_step._release_prerequisite_repair_step(release, "done"),
            "step6",
        )

    def test_done_state_is_rewound_to_earliest_stale_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report)
            state["state"].update({
                "current_step": "done",
                "completed_step": "step6",
                "status": "completed",
                "pending_interaction": {"step_id": "step6"},
            })
            state["step5"]["input"] = {"step0_confirmed": True}
            release = {
                "step4": {"status": "current"},
                "step5": {"status": "stale"},
                "step6": {"status": "stale"},
            }
            with (
                patch.object(
                    run_step,
                    "reconcile_current_release",
                    return_value=release,
                ),
                patch.object(run_step, "save_main_state"),
                patch.object(run_step, "clear_interaction_file"),
            ):
                result = run_step._apply_downstream_release_startup_state(
                    args=SimpleNamespace(step="auto"),
                    main_state=state,
                    report_dir=report,
                    structured_user_response={"action": "continue"},
                    has_structured_response=True,
                )

        self.assertEqual(result["forced_step_id"], "step5")
        self.assertTrue(result["discard_structured_response"])
        self.assertEqual(state["state"]["current_step"], "step5")
        self.assertEqual(state["state"]["completed_step"], "step4")
        self.assertIsNone(state["state"]["pending_interaction"])

    def test_done_state_rewinds_when_downstream_gate_policy_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            state = run_step.new_main_state(report)
            state["state"].update({
                "current_step": "done",
                "completed_step": "step6",
                "status": "completed",
            })
            state["step5"]["input"] = {"step0_confirmed": True}
            release = {
                "step4": {"status": "current"},
                "step5": {"status": "current"},
                "step6": {"status": "current"},
            }
            with (
                patch.object(
                    run_step,
                    "reconcile_current_release",
                    return_value=release,
                ),
                patch.object(
                    run_step,
                    "_downstream_gate_policy_is_current",
                    side_effect=lambda _report, stage, **_kwargs: (
                        stage != "step5"
                    ),
                ),
                patch.object(run_step, "save_main_state"),
                patch.object(run_step, "clear_interaction_file"),
            ):
                result = run_step._apply_downstream_release_startup_state(
                    args=SimpleNamespace(step="auto"),
                    main_state=state,
                    report_dir=report,
                    structured_user_response=None,
                    has_structured_response=False,
                    manifest_steps={
                        "step5": {"gate": "binary_report"},
                        "step6": {"gate": "binary_final_report"},
                    },
                    strict_risk_gate=True,
                )

        self.assertEqual(result["forced_step_id"], "step5")
        self.assertEqual(
            result["release"]["step5"]["reason"],
            "gate_policy_mismatch",
        )
        self.assertEqual(state["state"]["current_step"], "step5")

    def test_landing_suppresses_preserved_release_at_in_progress_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            for relative in (
                "deliverables/report.md",
                "evidence/call_chain/alerts.csv",
                "evidence/api_changes/all_changed_apis.csv",
            ):
                path = report / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("old", encoding="utf-8")
            active = (
                report
                / run_step.BINARY_OUTPUT_RELATIVE_PATH
                / "active_binary_generation.json"
            )
            active.parent.mkdir(parents=True, exist_ok=True)
            active.write_text("{}", encoding="utf-8")
            state = run_step.new_main_state(report)
            state["state"].update({
                "current_step": "step5",
                "completed_step": "step4",
            })
            release = {
                "step4": {"status": "current"},
                "step5": {"status": "current"},
                "step6": {"status": "current"},
            }
            with patch.object(
                run_step,
                "reconcile_current_release",
                return_value=release,
            ):
                rows = run_step._landing_existing_artifact_rows(
                    report, state=state
                )

        paths = {relative for _label, relative in rows}
        self.assertIn(
            "evidence/api_changes/all_changed_apis.csv", paths
        )
        self.assertNotIn("evidence/call_chain/alerts.csv", paths)
        self.assertNotIn("deliverables/report.md", paths)

    def test_protocol_landing_hides_stale_fixed_downstream_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / ".upgrade-report"
            for relative in (
                "deliverables/report.md",
                "evidence/call_chain/alerts.csv",
                "evidence/api_changes/all_changed_apis.csv",
            ):
                path = report / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("old", encoding="utf-8")
            run_step.ensure_report_publication_protocol(report)
            release = {
                "step4": {"status": "current"},
                "step5": {"status": "stale"},
                "step6": {"status": "stale"},
            }
            with patch.object(
                run_step,
                "reconcile_current_release",
                return_value=release,
            ):
                rows = run_step._landing_existing_artifact_rows(report)

        paths = {relative for _label, relative in rows}
        self.assertIn(
            "evidence/api_changes/all_changed_apis.csv", paths
        )
        self.assertNotIn("evidence/call_chain/alerts.csv", paths)
        self.assertNotIn("deliverables/report.md", paths)


if __name__ == "__main__":
    unittest.main()
