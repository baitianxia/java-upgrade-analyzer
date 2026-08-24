from __future__ import annotations

from contextlib import ExitStack, nullcontext
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import binary_report


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


class BinaryReportResidualBoundaryTest(unittest.TestCase):
    def assert_reason(self, expected: str, action) -> binary_report.BinaryReportError:
        with self.assertRaises(binary_report.BinaryReportError) as captured:
            action()
        self.assertEqual(captured.exception.reason_code, expected)
        return captured.exception

    def test_empty_gate_binding_release_fields_and_protocol_toctou(self):
        payload = {
            "transaction_id": "1" * 32,
            "binding": {},
            "published_content_identity": SHA_A,
        }
        receipt = binary_report._new_report_gate_receipt(
            payload, gate_name="binary_report", strict_risk_gate=True,
        )
        self.assertIsNone(receipt["gate_implementation_identity"])
        self.assertEqual(
            binary_report._validate_report_gate_receipt(
                receipt, payload=payload,
            ),
            receipt,
        )

        release_receipt = {
            "transaction_id": "1" * 32,
            "committed_receipt_identity": SHA_A,
            "published_content_identity": SHA_B,
            "binding": {"publication_input_identity": SHA_C},
        }
        for field in (
            "transaction_id",
            "committed_receipt_identity",
            "published_content_identity",
        ):
            mutation = {**release_receipt, field: None}
            with self.subTest(empty_release_field=field):
                self.assert_reason(
                    "BINARY_GLOBAL_RELEASE_RECEIPT_INVALID",
                    lambda mutation=mutation: binary_report._release_stage_from_receipt(
                        "step4", mutation,
                    ),
                )

        self.assertFalse(binary_report._receipt_matches_release_core(
            {}, {"result_generation_identity": SHA_A},
        ))
        self.assertIsNone(binary_report._complete_release_snapshot({
            "active_core": {},
            "step4": None,
            "step5": {"status": "current"},
            "step6": {"status": "current"},
            "release_identity": SHA_A,
        }))

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()

            def exists(path):
                return Path(path).name == "s5_query_index.json"

            with patch.object(
                binary_report, "_publication_path_exists", side_effect=exists,
            ), patch.object(
                binary_report, "_read_private_publication_json", return_value=None,
            ):
                self.assertFalse(
                    binary_report.report_uses_release_protocol(report)
                )

    def test_binding_fallbacks_snapshot_errors_and_directory_copy_absence(self):
        loaded = {
            "manifest": {"result_generation_identity": None},
            "active": {
                "validation_run_identity": SHA_A,
                "validation_result_sha256": SHA_B,
            },
        }
        error = self.assert_reason(
            "BINARY_STEP4_PUBLICATION_BINDING_INVALID",
            lambda: binary_report._loaded_step4_publication_binding(loaded),
        )
        self.assertEqual(str(error), "")

        identity = binary_report._step6_publication_input_identity(
            {
                "manifest": {"result_generation_identity": SHA_A},
                "active": {
                    "validation_run_identity": SHA_B,
                    "validation_result_sha256": SHA_C,
                    "activation_identity": None,
                },
            },
            {"committed_receipt_identity": SHA_A},
            {
                "committed_receipt_identity": SHA_B,
                "published_content_identity": SHA_C,
                "binding": None,
            },
            {},
        )
        self.assertTrue(binary_report._is_sha256_identity(identity))

        valid_loaded = {
            "manifest": {"result_generation_identity": SHA_A},
            "active": {
                "validation_run_identity": SHA_B,
                "validation_result_sha256": SHA_C,
                "activation_identity": SHA_A,
            },
        }
        core = {
            "result_generation_identity": SHA_A,
            "validation_run_identity": SHA_B,
            "validation_result_sha256": SHA_C,
            "upstream_publication_receipt_identity": SHA_B,
        }
        snapshots = [
            {"binding": {}, "transaction_id": None},
            {
                "binding": {
                    **core,
                    "activation_identity": SHA_C,
                    "publication_input_identity": SHA_A,
                },
                "transaction_id": None,
            },
            {
                "binding": {
                    **core,
                    "activation_identity": SHA_A,
                    "publication_input_identity": "invalid",
                },
                "transaction_id": None,
            },
            {
                "binding": {
                    **core,
                    "activation_identity": SHA_A,
                    "publication_input_identity": SHA_A,
                },
                "gate_receipt": {"gate_name": "binary_report"},
                "snapshot_destinations": (),
                "transaction_id": None,
            },
        ]
        for snapshot in snapshots:
            with self.subTest(snapshot=snapshot):
                error = self.assert_reason(
                    (
                        "BINARY_STEP5_PUBLICATION_SNAPSHOT_INVALID"
                        if "snapshot_destinations" in snapshot
                        else "BINARY_STEP5_PUBLICATION_BINDING_MISMATCH"
                    ),
                    lambda snapshot=snapshot: binary_report._require_step5_snapshot_binding(
                        valid_loaded,
                        {"committed_receipt_identity": SHA_B},
                        snapshot,
                    ),
                )
                self.assertEqual(str(error), "")

        with patch.object(
            binary_report, "_publication_path_exists", return_value=False,
        ), patch.object(
            binary_report, "_copy_report_directory_secure",
        ) as copy:
            binary_report._copy_step6_input_directory(
                Path("/missing"), Path("/unused"),
            )
        copy.assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            destination = root / "parent" / "destination"
            with patch.object(
                binary_report, "_publication_path_exists", return_value=True,
            ), patch.object(
                binary_report, "_copy_report_directory_secure",
            ) as copy:
                binary_report._copy_step6_input_directory(source, destination)
            self.assertTrue(destination.parent.is_dir())
            copy.assert_called_once_with(source, destination)

    def test_downstream_binding_activation_and_core_matrix(self):
        loaded = {
            "manifest": {"result_generation_identity": SHA_A},
            "active": {
                "validation_run_identity": SHA_B,
                "validation_result_sha256": SHA_C,
                "activation_identity": SHA_A,
            },
        }
        core = {
            "result_generation_identity": SHA_A,
            "validation_run_identity": SHA_B,
            "validation_result_sha256": SHA_C,
        }
        self.assertFalse(
            binary_report._downstream_publication_binding_matches_loaded(
                {**core, "validation_result_sha256": SHA_A}, loaded,
            )
        )
        self.assertTrue(
            binary_report._downstream_publication_binding_matches_loaded(
                {**core, "activation_identity": SHA_A}, loaded,
            )
        )
        self.assertFalse(
            binary_report._downstream_publication_binding_matches_loaded(
                {**core, "activation_identity": SHA_B}, loaded,
            )
        )

        loaded_without_activation = {
            **loaded,
            "active": {**loaded["active"], "activation_identity": None},
        }
        self.assertTrue(
            binary_report._downstream_publication_binding_matches_loaded(
                core, loaded_without_activation,
            )
        )
        self.assertTrue(
            binary_report._downstream_publication_binding_matches_loaded(
                {**core, "activation_identity": SHA_A},
                loaded_without_activation,
            )
        )
        self.assertFalse(
            binary_report._downstream_publication_binding_matches_loaded(
                {**core, "activation_identity": "invalid"},
                loaded_without_activation,
            )
        )

    def test_stage_directory_group_empty_duplicate_path_collision_and_rollback_matrix(self):
        self.assertIsNone(binary_report._stage_directory_group(()))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            destination = root / "duplicate"
            writer = lambda _stage, _prepared: None
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_DUPLICATE",
                lambda: binary_report._stage_directory_group((
                    (destination, writer), (destination, writer),
                )),
            )

            file_destination = root / "file-destination"
            file_destination.write_text("not a directory", encoding="utf-8")
            self.assert_reason(
                "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._stage_directory_group((
                    (file_destination, writer),
                )),
            )

            existing_directory = root / "existing-directory"
            existing_directory.mkdir()

            def write_content(stage, _prepared):
                (Path(stage) / "content.txt").write_text(
                    "published", encoding="utf-8",
                )

            self.assertIsNone(binary_report._stage_directory_group((
                (existing_directory, write_content),
            )))
            self.assertEqual(
                (existing_directory / "content.txt").read_text(
                    encoding="utf-8",
                ),
                "published",
            )

            symlink_target = root / "symlink-target"
            symlink_target.mkdir()
            symlink_destination = root / "symlink-destination"
            symlink_destination.symlink_to(
                symlink_target, target_is_directory=True,
            )
            with patch.object(
                binary_report,
                "_normalize_publication_destination",
                side_effect=lambda value, **_kwargs: Path(value),
            ):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_TARGET_INVALID",
                    lambda: binary_report._stage_directory_group((
                        (symlink_destination, writer),
                    )),
                )

        for collision_kind in ("stage", "backup"):
            with self.subTest(collision_kind=collision_kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                destination = root / "report"
                transaction_id = "1" * 32
                token = binary_report._publication_group_token([destination])
                collision = destination.parent / (
                    f".jua-br-{token}-{transaction_id}-0.{collision_kind}"
                )
                collision.mkdir()
                with patch.object(
                    binary_report.uuid,
                    "uuid4",
                    return_value=SimpleNamespace(hex=transaction_id),
                ):
                    self.assert_reason(
                        "BINARY_REPORT_PUBLICATION_TRANSACTION_COLLISION",
                        lambda: binary_report._stage_directory_group((
                            (destination, lambda _stage, _prepared: None),
                        )),
                    )

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory).resolve() / "rollback"

            def fail_writer(_stage, _prepared):
                raise RuntimeError("writer failed")

            with patch.object(
                binary_report,
                "_recover_publication_transaction",
                side_effect=RuntimeError("rollback failed"),
            ):
                error = self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_ROLLBACK_FAILED",
                    lambda: binary_report._stage_directory_group((
                        (destination, fail_writer),
                    )),
                )
            self.assertEqual(str(error), str(destination))

    def test_complete_step4_commit_validation_cleanup_and_receipt_matrix(self):
        report = Path("/virtual/report")
        transaction_id = "1" * 32
        binding = {"result_generation_identity": SHA_A}
        loaded = {"loaded": True}

        def invoke(
            *, transaction, binding_matches=True, mark_error=None,
            transaction_state="absent", committed_identity=SHA_A,
            release_identity=SHA_A,
        ):
            rollback = unittest.mock.MagicMock()
            with patch.object(
                binary_report,
                "_active_generation_publication_lock",
                return_value=nullcontext(),
            ), patch.object(
                binary_report,
                "report_publication_transaction_receipt",
                return_value=transaction,
            ), patch.object(
                binary_report, "load_validated_generation", return_value=loaded,
            ), patch.object(
                binary_report,
                "_step4_publication_binding_matches_loaded",
                return_value=binding_matches,
            ), patch.object(
                binary_report,
                "rollback_report_publication",
                rollback,
            ), patch.object(
                binary_report,
                "mark_report_publication_gate_passed",
                side_effect=mark_error,
                return_value={"gate": "passed"},
            ), patch.object(
                binary_report, "publish_report_publication",
            ), patch.object(
                binary_report, "commit_report_publication",
            ), patch.object(
                binary_report,
                "report_publication_committed_receipt",
                return_value={
                    "committed_receipt_identity": committed_identity,
                },
            ), patch.object(
                binary_report,
                "reconcile_current_release",
                return_value={
                    "step4": {
                        "committed_receipt_identity": release_identity,
                    },
                },
            ), patch.object(
                binary_report,
                "report_publication_transaction_state",
                return_value=transaction_state,
            ):
                result = binary_report.complete_step4_report_publication_after_gate(
                    report,
                    expected_transaction_id=transaction_id,
                    expected_binding=binding,
                    gate_name="binary_generation",
                    strict_risk_gate=True,
                    workflow_lock_held=True,
                )
            return result, rollback

        for transaction, matches in [
            ({"state": None, "binding": binding}, True),
            ({"state": "pending_gate", "binding": {}}, False),
        ]:
            with self.subTest(transaction=transaction, matches=matches):
                with self.assertRaises(binary_report.BinaryReportError):
                    invoke(transaction=transaction, binding_matches=matches)

        for state, expected_rollbacks in [("absent", 0), ("pending_gate", 1)]:
            rollback = unittest.mock.MagicMock()
            with self.subTest(cleanup_state=state), patch.object(
                binary_report,
                "_active_generation_publication_lock",
                return_value=nullcontext(),
            ), patch.object(
                binary_report,
                "report_publication_transaction_receipt",
                return_value={"state": "pending_gate", "binding": binding},
            ), patch.object(
                binary_report, "load_validated_generation", return_value=loaded,
            ), patch.object(
                binary_report,
                "_step4_publication_binding_matches_loaded",
                return_value=True,
            ), patch.object(
                binary_report,
                "mark_report_publication_gate_passed",
                side_effect=RuntimeError("gate failed"),
            ), patch.object(
                binary_report,
                "report_publication_transaction_state",
                return_value=state,
            ), patch.object(
                binary_report, "rollback_report_publication", rollback,
            ):
                with self.assertRaisesRegex(RuntimeError, "gate failed"):
                    binary_report.complete_step4_report_publication_after_gate(
                        report,
                        expected_transaction_id=transaction_id,
                        expected_binding=binding,
                        gate_name="binary_generation",
                        strict_risk_gate=True,
                        workflow_lock_held=True,
                    )
            self.assertEqual(rollback.call_count, expected_rollbacks)

        result, rollback = invoke(
            transaction={"state": "pending_gate", "binding": binding},
        )
        self.assertEqual(result["stage"], "step4")
        rollback.assert_not_called()
        with self.assertRaises(binary_report.BinaryReportError):
            invoke(
                transaction={"state": "pending_gate", "binding": binding},
                release_identity=SHA_B,
            )

    def test_direct_step4_publication_candidate_gate_and_cleanup_matrix(self):
        report = Path("/virtual/report")
        output = report / "evidence/api_changes"
        transaction = {
            "transaction_id": "1" * 32,
            "binding": {"result_generation_identity": SHA_A},
            "published_content_identity": SHA_B,
        }

        def invoke(*, tx, candidate, state="absent", gate_error=None):
            rollback = unittest.mock.MagicMock()
            with patch.object(
                binary_report,
                "_standalone_report_workflow_lock",
                return_value=nullcontext(),
            ), patch.object(
                binary_report,
                "_report_publication_prepare_capability",
                return_value=nullcontext(),
            ), patch.object(
                binary_report,
                "prepare_step4_publication_candidate",
                return_value={"publication_transaction": tx, "value": 1},
            ), patch.object(
                binary_report,
                "materialize_report_publication_gate_candidate",
                return_value={"candidate_destinations": candidate},
            ), patch(
                "gate.gate_binary_generation", side_effect=gate_error,
            ), patch.object(
                binary_report,
                "complete_step4_report_publication_after_gate",
                return_value={
                    "publication_receipt": {"receipt": True},
                    "global_release": {"release": True},
                },
            ), patch.object(
                binary_report,
                "report_publication_transaction_state",
                return_value=state,
            ), patch.object(
                binary_report, "rollback_report_publication", rollback,
            ):
                result = binary_report.publish_step4(report, output)
            return result, rollback

        for state, expected_rollbacks in [("absent", 0), ("pending_gate", 1)]:
            with self.subTest(empty_transaction_state=state):
                rollback = unittest.mock.MagicMock()
                with patch.object(
                    binary_report,
                    "_standalone_report_workflow_lock",
                    return_value=nullcontext(),
                ), patch.object(
                    binary_report,
                    "_report_publication_prepare_capability",
                    return_value=nullcontext(),
                ), patch.object(
                    binary_report,
                    "prepare_step4_publication_candidate",
                    return_value={"publication_transaction": None},
                ), patch.object(
                    binary_report,
                    "materialize_report_publication_gate_candidate",
                    return_value={"candidate_destinations": None},
                ), patch.object(
                    binary_report,
                    "report_publication_transaction_state",
                    return_value=state,
                ), patch.object(
                    binary_report,
                    "rollback_report_publication",
                    rollback,
                ):
                    self.assert_reason(
                        "BINARY_STEP4_PUBLICATION_CANDIDATE_INCOMPLETE",
                        lambda: binary_report.publish_step4(report, output),
                    )
                self.assertEqual(rollback.call_count, expected_rollbacks)
                if expected_rollbacks:
                    self.assertEqual(
                        rollback.call_args.kwargs,
                        {
                            "expected_transaction_id": "",
                            "expected_binding": {},
                        },
                    )

        result, rollback = invoke(
            tx=transaction,
            candidate=["/candidate/api", "/candidate/source"],
        )
        self.assertIsNone(result["publication_transaction"])
        self.assertEqual(result["publication_receipt"], {"receipt": True})
        rollback.assert_not_called()

        with self.assertRaises(binary_report.BinaryReportError):
            invoke(
                tx=transaction,
                candidate=["/candidate/api", "/candidate/source"],
                state="pending_gate",
                gate_error=SystemExit(7),
            )

    def test_direct_step5_publication_candidate_gate_and_cleanup_matrix(self):
        report = Path("/virtual/report")
        output = report / "evidence/call_chain"
        transaction = {
            "transaction_id": "1" * 32,
            "binding": {"result_generation_identity": SHA_A},
            "published_content_identity": SHA_B,
        }

        def contexts():
            return (
                patch.object(
                    binary_report,
                    "_standalone_report_workflow_lock",
                    return_value=nullcontext(),
                ),
                patch.object(
                    binary_report,
                    "_report_publication_prepare_capability",
                    return_value=nullcontext(),
                ),
            )

        for state, expected_rollbacks in [("absent", 0), ("pending_gate", 1)]:
            rollback = unittest.mock.MagicMock()
            first, second = contexts()
            with self.subTest(empty_transaction_state=state), first, second, patch.object(
                binary_report,
                "prepare_step5_publication_candidate",
                return_value={"publication_transaction": None},
            ), patch.object(
                binary_report,
                "materialize_report_publication_gate_candidate",
                return_value={"candidate_destinations": None},
            ), patch.object(
                binary_report,
                "report_publication_transaction_state",
                return_value=state,
            ), patch.object(
                binary_report, "rollback_report_publication", rollback,
            ):
                self.assert_reason(
                    "BINARY_STEP5_PUBLICATION_CANDIDATE_INCOMPLETE",
                    lambda: binary_report.publish_step5(report, output),
                )
            self.assertEqual(rollback.call_count, expected_rollbacks)
            if expected_rollbacks:
                self.assertEqual(
                    rollback.call_args.kwargs,
                    {"expected_transaction_id": "", "expected_binding": {}},
                )

        for gate_error in (None, SystemExit(9)):
            rollback = unittest.mock.MagicMock()
            first, second = contexts()
            with self.subTest(gate_error=gate_error), first, second, patch.object(
                binary_report,
                "prepare_step5_publication_candidate",
                return_value={
                    "publication_transaction": transaction, "value": 1,
                },
            ), patch.object(
                binary_report,
                "materialize_report_publication_gate_candidate",
                return_value={
                    "candidate_destinations": [
                        "/candidate/call", "/candidate/binary",
                        "/candidate/index",
                    ],
                },
            ), patch(
                "gate.gate_binary_report", side_effect=gate_error,
            ), patch.object(
                binary_report,
                "complete_downstream_report_publication_after_gate",
                return_value={
                    "publication_receipt": {"receipt": True},
                    "global_release": {"release": True},
                },
            ), patch.object(
                binary_report,
                "report_publication_transaction_state",
                return_value="pending_gate",
            ), patch.object(
                binary_report, "rollback_report_publication", rollback,
            ):
                if gate_error is None:
                    result = binary_report.publish_step5(report, output)
                    self.assertIsNone(result["publication_transaction"])
                    rollback.assert_not_called()
                else:
                    self.assert_reason(
                        "BINARY_STEP5_PUBLICATION_GATE_FAILED",
                        lambda: binary_report.publish_step5(report, output),
                    )
                    rollback.assert_called_once()

    def test_step5_locked_reader_target_binding_snapshot_and_success_matrix(self):
        report = Path("/virtual/report")
        output = report / "evidence/call_chain"
        loaded = {"loaded": True}

        with patch.object(
            binary_report, "_ensure_publication_protocol_marker",
        ):
            self.assert_reason(
                "BINARY_STEP5_PUBLICATION_TARGET_INVALID",
                lambda: binary_report._publish_step5_with_lock(
                    report, report / "wrong",
                ),
            )

        def invoke(*, receipt, matches):
            with patch.object(
                binary_report, "_ensure_publication_protocol_marker",
            ), patch.object(
                binary_report, "require_current_release_stage",
            ), patch.object(
                binary_report, "load_validated_generation", return_value=loaded,
            ), patch.object(
                binary_report,
                "materialize_report_publication_committed_snapshot",
                return_value=receipt,
            ), patch.object(
                binary_report,
                "_step4_publication_binding_matches_loaded",
                return_value=matches,
            ), patch.object(
                binary_report,
                "_publish_step5_from_snapshot",
                return_value={"published": True},
            ) as publish:
                result = binary_report._publish_step5_with_lock(
                    report, output,
                )
            return result, publish

        error = self.assert_reason(
            "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
            lambda: invoke(
                receipt={"binding": None, "transaction_id": None},
                matches=False,
            ),
        )
        self.assertEqual(str(error), "")

        error = self.assert_reason(
            "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
            lambda: invoke(
                receipt={"binding": {}, "transaction_id": "1" * 32},
                matches=False,
            ),
        )
        self.assertEqual(str(error), "1" * 32)

        self.assert_reason(
            "BINARY_STEP4_PUBLICATION_SNAPSHOT_INVALID",
            lambda: invoke(
                receipt={
                    "binding": {}, "transaction_id": "1" * 32,
                    "snapshot_destinations": None,
                },
                matches=True,
            ),
        )

        result, publish = invoke(
            receipt={
                "binding": {}, "transaction_id": "1" * 32,
                "snapshot_destinations": ["/snapshot/api", "/snapshot/source"],
            },
            matches=True,
        )
        self.assertEqual(result, {"published": True})
        self.assertEqual(
            publish.call_args.kwargs["step4_api_changes_dir"],
            Path("/snapshot/api"),
        )

    def test_step6_locked_reader_target_binding_snapshot_and_copy_matrix(self):
        report = Path("/virtual/report")
        findings_path = report / ".runtime/findings/s6_findings.json"
        report_path = report / "deliverables/report.md"
        loaded = {"loaded": True}

        for findings, rendered in [
            (report / "wrong.json", report_path),
            (findings_path, report / "wrong.md"),
        ]:
            with self.subTest(findings=findings, report=rendered), patch.object(
                binary_report, "_ensure_publication_protocol_marker",
            ):
                self.assert_reason(
                    "BINARY_STEP6_PUBLICATION_TARGET_INVALID",
                    lambda findings=findings, rendered=rendered: binary_report._publish_step6_with_lock(
                        report,
                        findings,
                        rendered,
                        prepare_candidate_only=True,
                    ),
                )

        def invoke(*, step4, matches, step5_sources=None):
            copy = unittest.mock.MagicMock()
            with patch.object(
                binary_report, "_ensure_publication_protocol_marker",
            ), patch.object(
                binary_report, "require_current_release_stage",
            ), patch.object(
                binary_report, "load_validated_generation", return_value=loaded,
            ), patch.object(
                binary_report,
                "materialize_report_publication_committed_snapshot",
                side_effect=[step4, {"step5": True}],
            ), patch.object(
                binary_report,
                "_step4_publication_binding_matches_loaded",
                return_value=matches,
            ), patch.object(
                binary_report,
                "_require_step5_snapshot_binding",
                return_value=tuple(step5_sources or (
                    "/snapshot/call", "/snapshot/binary", "/snapshot/index",
                )),
            ), patch.object(
                binary_report, "_copy_step6_input_directory", copy,
            ), patch.object(
                binary_report,
                "_materialize_step6_upstream_evidence",
                return_value={},
            ), patch.object(
                binary_report,
                "_collect_step6_findings_for_publication",
                return_value={},
            ), patch.object(
                binary_report,
                "_step6_publication_input_identity",
                return_value=SHA_A,
            ), patch.object(
                binary_report,
                "_render_and_publish_step6_from_snapshots",
                return_value={"rendered": True},
            ):
                result = binary_report._publish_step6_with_lock(
                    report,
                    findings_path,
                    report_path,
                    prepare_candidate_only=True,
                )
            return result, copy

        error = self.assert_reason(
            "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
            lambda: invoke(
                step4={"binding": None, "transaction_id": None},
                matches=False,
            ),
        )
        self.assertEqual(str(error), "")
        error = self.assert_reason(
            "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
            lambda: invoke(
                step4={"binding": {}, "transaction_id": "1" * 32},
                matches=False,
            ),
        )
        self.assertEqual(str(error), "1" * 32)
        error = self.assert_reason(
            "BINARY_STEP4_PUBLICATION_SNAPSHOT_INVALID",
            lambda: invoke(
                step4={
                    "binding": {}, "transaction_id": None,
                    "snapshot_destinations": None,
                },
                matches=True,
            ),
        )
        self.assertEqual(str(error), "")
        error = self.assert_reason(
            "BINARY_STEP4_PUBLICATION_SNAPSHOT_INVALID",
            lambda: invoke(
                step4={
                    "binding": {}, "transaction_id": "1" * 32,
                    "snapshot_destinations": None,
                },
                matches=True,
            ),
        )
        self.assertEqual(str(error), "1" * 32)

        result, copy = invoke(
            step4={
                "binding": {}, "transaction_id": "1" * 32,
                "snapshot_destinations": ["/snapshot/api", "/snapshot/source"],
            },
            matches=True,
        )
        self.assertEqual(result, {"rendered": True})
        self.assertEqual(copy.call_count, 5)

    def test_step6_render_activation_refresh_candidate_and_cleanup_matrix(self):
        report = Path("/virtual/report")
        findings_path = report / ".runtime/findings/s6_findings.json"
        report_path = report / "deliverables/report.md"
        step4 = {
            "transaction_id": "1" * 32, "binding": {},
        }
        step5 = {
            "transaction_id": "2" * 32, "binding": {},
            "committed_receipt_identity": SHA_B,
        }

        def loaded(activation):
            return {
                "manifest": {"result_generation_identity": SHA_A},
                "active": {
                    "validation_run_identity": SHA_B,
                    "validation_result_sha256": SHA_C,
                    "activation_identity": activation,
                },
            }

        observed_rollbacks = []

        def invoke(
            *, activation=SHA_A, refreshed_same=True,
            prepare=True, candidate=None, state="absent", api_count=0,
        ):
            original = loaded(activation)
            stage_transaction = {
                "transaction_id": "3" * 32,
                "binding": {"binding": True},
                "published_content_identity": SHA_C,
            }
            rollback = unittest.mock.MagicMock()
            observed_rollbacks.append(rollback)
            binding_values = (
                [{"core": 1}, {"core": 1}]
                if refreshed_same
                else [{"core": 1}, {"core": 2}]
            )
            with patch.object(
                binary_report, "_bind_step6_findings_to_release",
            ), patch.object(
                binary_report,
                "_write_step6_artifact_set",
                return_value=(
                    Path("/render/deliverables/report.md"),
                    Path("/render/.runtime/findings/s6_findings.json"),
                ),
            ), patch.object(
                binary_report,
                "_active_generation_publication_lock",
                return_value=nullcontext(),
            ), patch.object(
                binary_report, "load_validated_generation", return_value=original,
            ), patch.object(
                binary_report,
                "_loaded_step4_publication_binding",
                side_effect=binding_values,
            ), patch.object(
                binary_report, "report_publication_committed_receipt",
            ), patch.object(
                binary_report,
                "_stage_directory_group",
                return_value=stage_transaction,
            ), patch.object(
                binary_report,
                "materialize_report_publication_gate_candidate",
                return_value={"candidate_destinations": candidate},
            ), patch.object(
                binary_report,
                "_validate_step6_candidate_under_parent_workflow_lock",
            ), patch.object(
                binary_report,
                "complete_downstream_report_publication_after_gate",
                return_value={
                    "publication_receipt": {"receipt": True},
                    "global_release": {"release": True},
                },
            ), patch.object(
                binary_report,
                "report_publication_transaction_state",
                return_value=state,
            ), patch.object(
                binary_report, "rollback_report_publication", rollback,
            ):
                result = binary_report._render_and_publish_step6_from_snapshots(
                    report_root=report,
                    findings_path=findings_path,
                    report_path=report_path,
                    loaded=original,
                    render_root=Path("/render"),
                    findings={"call_chain_target_count": api_count},
                    step4_snapshot=step4,
                    step5_snapshot=step5,
                    step6_input_identity=SHA_A,
                    upstream_evidence_inputs={},
                    prepare_candidate_only=prepare,
                )
            return result, rollback

        for activation in (None, SHA_A):
            result, _rollback = invoke(activation=activation, prepare=True)
            self.assertIsNotNone(result["publication_transaction"])
        result, _rollback = invoke(prepare=True, api_count=3)
        self.assertEqual(result["api_count"], 3)

        self.assert_reason(
            "BINARY_STEP6_ACTIVE_GENERATION_CHANGED",
            lambda: invoke(refreshed_same=False),
        )

        for state, expected_rollbacks in [("absent", 0), ("pending_gate", 1)]:
            with self.subTest(candidate_state=state):
                with self.assertRaises(binary_report.BinaryReportError):
                    invoke(
                        prepare=False, candidate=None, state=state,
                    )
                self.assertEqual(
                    observed_rollbacks[-1].call_count, expected_rollbacks,
                )

        result, rollback = invoke(
            prepare=False,
            candidate=["/candidate/deliverables", "/candidate/findings"],
            state="pending_gate",
        )
        self.assertIsNone(result["publication_transaction"])
        rollback.assert_not_called()

    def test_downstream_recovery_falsy_state_and_disposition_matrix(self):
        report = Path("/virtual/report")

        def invoke(metadata, *, reconcile_release=False):
            with patch.object(
                binary_report,
                "_active_generation_publication_lock",
                return_value=nullcontext(),
            ), patch.object(
                binary_report,
                "report_publication_transaction_recovery_metadata",
                side_effect=metadata,
            ), patch.object(
                binary_report,
                "recover_report_publication",
                return_value=True,
            ), patch.object(
                binary_report,
                "reconcile_current_release",
                return_value={"release": True},
            ):
                return binary_report.recover_downstream_report_publications(
                    report,
                    workflow_lock_held=True,
                    reconcile_release=reconcile_release,
                )

        result = invoke([
            {},
            {
                "state": "committed",
                "transaction_id": "2" * 32,
                "binding": {},
            },
        ], reconcile_release=True)
        self.assertEqual(result["actions"][0]["disposition"], "finalized_committed")
        self.assertEqual(result["global_release"], {"release": True})

        result = invoke([
            {
                "state": "prepared",
                "transaction_id": "1" * 32,
                "binding": {},
            },
            {"state": "absent"},
        ])
        self.assertEqual(
            result["actions"][0]["disposition"],
            "rolled_back_uncommitted",
        )
        self.assertIsNone(result["global_release"])

    def test_global_release_reconciliation_receipt_and_descriptor_matrix(self):
        report = Path("/virtual/report")
        core = {"core": SHA_A}
        step4_base = {
            "gate_valid": True,
            "binding": {"core": SHA_A},
            "committed_receipt_identity": "s4",
        }

        def step5_receipt(
            *, gate=True, core_match=True, upstream="s4", identity="s5",
        ):
            return {
                "gate_valid": gate,
                "core_match": core_match,
                "binding": {
                    "upstream_publication_receipt_identity": upstream,
                },
                "committed_receipt_identity": identity,
            }

        def step6_receipt(
            *, gate=True, core_match=True, upstream="s5",
            publication_input="expected", identity="s6",
        ):
            return {
                "gate_valid": gate,
                "core_match": core_match,
                "binding": {
                    "upstream_publication_receipt_identity": upstream,
                    "publication_input_identity": publication_input,
                },
                "committed_receipt_identity": identity,
            }

        def stage_value(stage, receipt):
            return {
                "status": "current",
                "committed_receipt_identity": receipt.get(
                    "committed_receipt_identity"
                ),
                "stage": stage,
            }

        def invoke(
            *, step4=step4_base, step5=None, step6=None,
            step4_matches=True, previous=None, complete_snapshot=None,
        ):
            receipts = [step4, step5 or {}, step6 or {}]
            with patch.object(
                binary_report,
                "load_validated_generation",
                return_value={"loaded": True},
            ), patch.object(
                binary_report, "_active_release_core", return_value=core,
            ), patch.object(
                binary_report,
                "report_publication_committed_receipt",
                side_effect=receipts,
            ), patch.object(
                binary_report,
                "_receipt_has_formal_gate",
                side_effect=lambda receipt, _name: bool(
                    (receipt or {}).get("gate_valid")
                ),
            ), patch.object(
                binary_report,
                "_step4_publication_binding_matches_loaded",
                return_value=step4_matches,
            ), patch.object(
                binary_report,
                "_receipt_matches_release_core",
                side_effect=lambda receipt, _core: bool(
                    (receipt or {}).get("core_match", True)
                ),
            ), patch.object(
                binary_report,
                "_release_stage_from_receipt",
                side_effect=stage_value,
            ), patch.object(
                binary_report,
                "_step6_upstream_evidence_state",
                return_value={},
            ), patch.object(
                binary_report,
                "_step6_publication_input_identity",
                return_value="expected",
            ), patch.object(
                binary_report,
                "exclusive_file_lock",
                return_value=nullcontext(),
            ), patch.object(
                binary_report,
                "_read_private_publication_json",
                return_value=previous,
            ), patch.object(
                binary_report,
                "_validate_global_release",
                side_effect=lambda value: value,
            ), patch.object(
                binary_report,
                "_complete_release_snapshot",
                return_value=complete_snapshot,
            ), patch.object(
                binary_report, "_global_release_identity", return_value=SHA_A,
            ), patch.object(binary_report, "_atomic_json"):
                return binary_report._reconcile_current_release_with_workflow_lock(
                    report,
                )

        for step4, matches in [
            ({}, True),
            ({**step4_base, "gate_valid": False}, True),
            ({**step4_base, "binding": None}, False),
        ]:
            with self.subTest(step4=step4, matches=matches):
                self.assert_reason(
                    "BINARY_GLOBAL_RELEASE_STEP4_NOT_CURRENT",
                    lambda step4=step4, matches=matches: invoke(
                        step4=step4, step4_matches=matches,
                    ),
                )

        stale_release = invoke(step5={}, step6={})
        self.assertEqual(stale_release["step5"]["status"], "stale")
        self.assertEqual(stale_release["step6"]["status"], "stale")
        for receipt in [
            step5_receipt(gate=False),
            step5_receipt(core_match=False),
            {**step5_receipt(), "binding": None},
            step5_receipt(upstream="wrong"),
        ]:
            with self.subTest(stale_step5=receipt):
                release = invoke(step5=receipt)
                self.assertEqual(release["step5"]["status"], "stale")

        current_step5 = step5_receipt()
        current_step6 = step6_receipt()
        step5_only = invoke(step5=current_step5)
        self.assertEqual(step5_only["step5"]["status"], "current")
        self.assertEqual(step5_only["step6"]["status"], "stale")
        complete = invoke(step5=current_step5, step6=current_step6)
        self.assertEqual(complete["step5"]["status"], "current")
        self.assertEqual(complete["step6"]["status"], "current")
        for receipt in [
            step6_receipt(gate=False),
            step6_receipt(core_match=False),
            {**step6_receipt(), "binding": None},
            step6_receipt(upstream="wrong"),
            step6_receipt(publication_input="wrong"),
        ]:
            with self.subTest(stale_step6=receipt):
                release = invoke(step5=current_step5, step6=receipt)
                self.assertEqual(release["step6"]["status"], "stale")

        current4 = stage_value("step4", step4_base)
        current5 = stage_value("step5", current_step5)
        current6 = stage_value("step6", current_step6)
        exact_previous = {
            "active_core": core,
            "step4": current4,
            "step5": current5,
            "step6": current6,
            "release_sequence": 7,
            "previous_complete": None,
        }
        self.assertIs(
            invoke(
                step5=current_step5,
                step6=current_step6,
                previous=exact_previous,
            ),
            exact_previous,
        )

        previous_step5_current = {
            **exact_previous,
            "step6": binary_report._stale_release_stage(),
        }
        advanced = invoke(
            step5=step5_receipt(gate=False),
            previous=previous_step5_current,
        )
        self.assertEqual(advanced["step5"]["status"], "stale")
        with self.assertRaises(binary_report.BinaryReportError):
            invoke(
                step5=step5_receipt(core_match=False),
                previous=previous_step5_current,
            )

        previous_step6_current = dict(exact_previous)
        for receipt in [
            step6_receipt(gate=False),
            step6_receipt(publication_input="old"),
        ]:
            with self.subTest(advanced_step6=receipt):
                advanced = invoke(
                    step5=current_step5,
                    step6=receipt,
                    previous=previous_step6_current,
                )
                self.assertEqual(advanced["step6"]["status"], "stale")

        newer_step5 = step5_receipt(identity="new-s5")
        advanced = invoke(
            step5=newer_step5,
            step6=step6_receipt(core_match=False, upstream="new-s5"),
            previous=previous_step6_current,
        )
        self.assertEqual(advanced["step6"]["status"], "stale")
        with self.assertRaises(binary_report.BinaryReportError):
            invoke(
                step5=current_step5,
                step6=step6_receipt(core_match=False),
                previous=previous_step6_current,
            )

        previous_other_core = {
            **previous_step5_current,
            "active_core": {"core": SHA_B},
        }
        release = invoke(
            step5=step5_receipt(core_match=False),
            previous=previous_other_core,
        )
        self.assertEqual(release["step5"]["status"], "stale")

        previous_other_step4 = {
            **previous_step5_current,
            "step4": {**current4, "committed_receipt_identity": "old-s4"},
        }
        release = invoke(
            step5=step5_receipt(core_match=False),
            previous=previous_other_step4,
        )
        self.assertEqual(release["step5"]["status"], "stale")

        previous_only_step6_current = {
            **exact_previous,
            "step5": binary_report._stale_release_stage(),
        }
        with self.assertRaises(binary_report.BinaryReportError):
            invoke(
                step5=step5_receipt(core_match=False),
                step6=step6_receipt(),
                previous=previous_only_step6_current,
            )

        durable_complete = {"release_identity": SHA_C}
        release = invoke(
            step5=current_step5,
            step6=current_step6,
            previous={**exact_previous, "active_core": {"core": SHA_B}},
            complete_snapshot=durable_complete,
        )
        self.assertIs(release["previous_complete"], durable_complete)

    def test_downstream_gate_completion_state_content_cas_and_rollback_matrix(self):
        report = Path("/virtual/report")
        destinations = {
            "step4": (report / "step4",),
            "step5": (report / "step5",),
            "step6": (report / "step6",),
        }
        default_selection = {
            "schema": "java-upgrade-analyzer.binary-step5-selection.v1",
            "selected_coords": ["g:a:1"],
            "selected_names": ["a"],
        }
        missing = object()

        def invoke(
            *, stage="step5", workflow_lock_held=True,
            transaction_state="pending_gate", binding_value=missing,
            published_identity=SHA_B, candidate_value=missing,
            selection=missing, binding_matches=True,
            upstream_identity=SHA_A, live_identity=SHA_C,
            fail_at=None, failure_state="pending_gate",
            final_receipt_identity=SHA_A,
            release_receipt_identity=SHA_A, events=None,
        ):
            observed = events if events is not None else []
            upstream_stage = "step4" if stage == "step5" else "step5"
            if binding_value is missing:
                binding = {
                    "upstream_publication_receipt_identity": upstream_identity,
                    "publication_input_identity": SHA_C,
                }
            else:
                binding = binding_value
            if candidate_value is missing:
                candidate = {
                    "candidate_destinations": [
                        "/candidate/call", "/candidate/binary",
                        "/candidate/index",
                    ],
                }
            else:
                candidate = candidate_value
            selection_value = (
                default_selection if selection is missing else selection
            )
            release = {
                upstream_stage: {
                    "committed_receipt_identity": upstream_identity,
                },
            }
            global_release = {
                stage: {
                    "committed_receipt_identity": release_receipt_identity,
                },
            }

            def committed_receipt(raw_destinations):
                normalized = tuple(raw_destinations)
                if normalized == destinations["step4"]:
                    return {"committed_receipt_identity": "step4-receipt"}
                if stage == "step6" and normalized == destinations["step5"]:
                    return {"committed_receipt_identity": "step5-receipt"}
                return {
                    "committed_receipt_identity": final_receipt_identity,
                }

            def stage_action(name, value=None):
                def action(*_args, **_kwargs):
                    observed.append(name)
                    if fail_at == name:
                        raise OSError(f"{name} failed")
                    return value
                return action

            with ExitStack() as stack:
                stack.enter_context(patch.object(
                    binary_report, "_require_formal_publication_gate",
                    return_value=f"formal-{stage}",
                ))
                stack.enter_context(patch.object(
                    binary_report, "_standalone_report_workflow_lock",
                    return_value=nullcontext(),
                ))
                stack.enter_context(patch.object(
                    binary_report, "_step4_report_publication_destinations",
                    return_value=destinations["step4"],
                ))
                stack.enter_context(patch.object(
                    binary_report, "_step5_report_publication_destinations",
                    return_value=destinations["step5"],
                ))
                stack.enter_context(patch.object(
                    binary_report, "_step6_report_publication_destinations",
                    return_value=destinations["step6"],
                ))
                stack.enter_context(patch.object(
                    binary_report, "_active_generation_publication_lock",
                    return_value=nullcontext(),
                ))
                stack.enter_context(patch.object(
                    binary_report, "report_publication_transaction_receipt",
                    return_value={
                        "state": transaction_state,
                        "binding": binding,
                        "published_content_identity": published_identity,
                    },
                ))
                stack.enter_context(patch.object(
                    binary_report, "load_validated_generation",
                    return_value={"loaded": True},
                ))
                stack.enter_context(patch.object(
                    binary_report, "require_current_release_stage",
                    return_value=release,
                ))
                stack.enter_context(patch.object(
                    binary_report, "report_publication_committed_receipt",
                    side_effect=committed_receipt,
                ))
                stack.enter_context(patch.object(
                    binary_report,
                    "materialize_report_publication_gate_candidate",
                    return_value=candidate,
                ))
                stack.enter_context(patch.object(
                    binary_report, "_load_json", return_value=selection_value,
                ))
                stack.enter_context(patch.object(
                    binary_report, "_step5_publication_input_identity",
                    return_value=live_identity,
                ))
                stack.enter_context(patch.object(
                    binary_report, "_step6_publication_input_identity",
                    return_value=live_identity,
                ))
                stack.enter_context(patch.object(
                    binary_report, "_step6_upstream_evidence_state",
                    return_value={"evidence": "current"},
                ))
                stack.enter_context(patch.object(
                    binary_report,
                    "_downstream_publication_binding_matches_loaded",
                    return_value=binding_matches,
                ))
                stack.enter_context(patch.object(
                    binary_report, "mark_report_publication_gate_passed",
                    side_effect=stage_action("mark", {"gate": True}),
                ))
                stack.enter_context(patch.object(
                    binary_report, "publish_report_publication",
                    side_effect=stage_action("publish"),
                ))
                stack.enter_context(patch.object(
                    binary_report, "commit_report_publication",
                    side_effect=stage_action("commit"),
                ))
                stack.enter_context(patch.object(
                    binary_report, "report_publication_transaction_state",
                    return_value=failure_state,
                ))
                stack.enter_context(patch.object(
                    binary_report, "rollback_report_publication",
                    side_effect=stage_action("rollback"),
                ))
                stack.enter_context(patch.object(
                    binary_report, "reconcile_current_release",
                    return_value=global_release,
                ))
                return binary_report.complete_downstream_report_publication_after_gate(
                    report,
                    stage,
                    expected_transaction_id="1" * 32,
                    expected_binding={},
                    gate_name=f"gate-{stage}",
                    strict_risk_gate=stage == "step6",
                    workflow_lock_held=workflow_lock_held,
                )

        with self.assertRaises(ValueError):
            binary_report.complete_downstream_report_publication_after_gate(
                report,
                "step4",
                expected_transaction_id="1" * 32,
                expected_binding={},
                gate_name="binary_generation",
                strict_risk_gate=False,
                workflow_lock_held=True,
            )

        for stage, workflow_lock_held in (("step5", False), ("step6", True)):
            with self.subTest(success_stage=stage):
                result = invoke(
                    stage=stage, workflow_lock_held=workflow_lock_held,
                )
                self.assertEqual(result["stage"], stage)
                self.assertEqual(result["gate_receipt"], {"gate": True})

        for state, expected_detail in (("", "absent"), ("prepared", "prepared")):
            with self.subTest(transaction_state=state):
                error = self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_STATE_INVALID",
                    lambda state=state: invoke(transaction_state=state),
                )
                self.assertEqual(str(error), expected_detail)

        for candidate in (
            {"candidate_destinations": None},
            {"candidate_destinations": ["/one", "/two"]},
        ):
            with self.subTest(candidate=candidate):
                self.assert_reason(
                    "BINARY_STEP5_PUBLICATION_SNAPSHOT_INVALID",
                    lambda candidate=candidate: invoke(
                        candidate_value=candidate, published_identity=None,
                    ),
                )

        invalid_selections = [
            {**default_selection, "schema": "wrong"},
            {**default_selection, "selected_coords": None},
            {**default_selection, "selected_names": None},
            {**default_selection, "selected_coords": [1]},
            {**default_selection, "selected_names": [1]},
        ]
        for selection in invalid_selections:
            with self.subTest(selection=selection):
                self.assert_reason(
                    "BINARY_STEP5_PUBLICATION_CONTENT_MISMATCH",
                    lambda selection=selection: invoke(selection=selection),
                )

        binding_failures = [
            {"binding_matches": False},
            {"binding_value": {
                "upstream_publication_receipt_identity": SHA_B,
                "publication_input_identity": SHA_C,
            }},
            {"binding_value": {
                "upstream_publication_receipt_identity": SHA_A,
                "publication_input_identity": "not-a-sha",
            }},
            {"live_identity": SHA_B},
            {"binding_value": None},
        ]
        for options in binding_failures:
            events = []
            with self.subTest(binding_failure=options):
                self.assert_reason(
                    "BINARY_REPORT_PUBLICATION_UPSTREAM_CHANGED",
                    lambda options=options: invoke(
                        **options, events=events,
                    ),
                )
                self.assertEqual(events, ["rollback"])

        for fail_at, failure_state, expected_rollback in (
            ("mark", "pending_gate", True),
            ("publish", "absent", False),
            ("commit", "committed", False),
        ):
            events = []
            with self.subTest(fail_at=fail_at, failure_state=failure_state):
                with self.assertRaisesRegex(OSError, f"{fail_at} failed"):
                    invoke(
                        fail_at=fail_at,
                        failure_state=failure_state,
                        events=events,
                    )
                self.assertEqual("rollback" in events, expected_rollback)

        self.assert_reason(
            "BINARY_GLOBAL_RELEASE_STAGE_RECEIPT_MISMATCH",
            lambda: invoke(
                final_receipt_identity=SHA_A,
                release_receipt_identity=SHA_B,
            ),
        )

    def test_step6_candidate_binding_files_content_rebuild_and_byte_matrix(self):
        required = (
            "report.md",
            "all-affected-dependencies.md",
            "all-affected-dependencies.csv",
            "all-impact-details.md",
            "all-impact-details.csv",
            "analysis-scope.md",
        )
        upstream_evidence = {"evidence/input.csv": {
            "status": "present", "content_identity": SHA_A,
        }}
        expected_binding = {
            "core": SHA_A,
            "upstream_publication_receipt_identity": SHA_B,
            "publication_input_identity": SHA_C,
        }
        base_findings = {
            "schema": "java-upgrade-analyzer.binary-findings.v2",
            "authority": "binary_first",
            "result_generation_identity": SHA_A,
            "step4_publication_receipt_identity": "step4-receipt",
            "step5_publication_receipt_identity": "step5-receipt",
            "step6_publication_input_identity": SHA_C,
            "step6_upstream_evidence_inputs": upstream_evidence,
            "generated_at": "2026-08-23T12:00:00+08:00",
        }
        missing = object()

        def invoke(
            *, binding=missing, missing_deliverable=None,
            findings_exists=True, findings=missing,
            step4_binding=None, step4_binding_matches=True,
            step4_sources=missing, step4_transaction_id="step4-tx",
            rebuilt_upstream=missing, rebuilt_findings=missing,
            directory_identities=missing,
        ):
            binding_value = expected_binding if binding is missing else binding
            findings_value = base_findings if findings is missing else findings
            rebuilt_findings_value = (
                findings_value if rebuilt_findings is missing
                else rebuilt_findings
            )
            sources = (
                ["/snapshot/api", "/snapshot/source"]
                if step4_sources is missing else step4_sources
            )
            rebuilt_evidence_value = (
                upstream_evidence if rebuilt_upstream is missing
                else rebuilt_upstream
            )
            identities = (
                [SHA_A, SHA_A, SHA_B, SHA_B]
                if directory_identities is missing
                else directory_identities
            )
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                report = root / "report"
                deliverables = root / "candidate-deliverables"
                findings_dir = root / "candidate-findings"
                report.mkdir()
                deliverables.mkdir()
                findings_dir.mkdir()
                for name in required:
                    if name != missing_deliverable:
                        (deliverables / name).write_text(
                            "candidate", encoding="utf-8",
                        )
                if findings_exists:
                    (findings_dir / "s6_findings.json").write_text(
                        "{}", encoding="utf-8",
                    )
                step4_snapshot = {
                    "binding": step4_binding,
                    "transaction_id": step4_transaction_id,
                    "snapshot_destinations": sources,
                }
                step5_snapshot = {"snapshot": "step5"}
                with ExitStack() as stack:
                    stack.enter_context(patch.object(
                        binary_report, "require_current_release_stage",
                        return_value={"step5": {
                            "committed_receipt_identity": SHA_B,
                        }},
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "load_validated_generation",
                        return_value={"manifest": {
                            "result_generation_identity": SHA_A,
                        }},
                    ))
                    stack.enter_context(patch.object(
                        binary_report,
                        "_step4_report_publication_destinations",
                        return_value=(report / "step4",),
                    ))
                    stack.enter_context(patch.object(
                        binary_report,
                        "_step5_report_publication_destinations",
                        return_value=(report / "step5",),
                    ))
                    stack.enter_context(patch.object(
                        binary_report,
                        "report_publication_committed_receipt",
                        side_effect=[
                            {"committed_receipt_identity": "step4-receipt"},
                            {"committed_receipt_identity": "step5-receipt"},
                        ],
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_step6_upstream_evidence_state",
                        return_value=upstream_evidence,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_step6_publication_input_identity",
                        return_value=SHA_C,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_active_release_core",
                        return_value={"core": SHA_A},
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_load_json",
                        side_effect=[findings_value, rebuilt_findings_value],
                    ))
                    stack.enter_context(patch.object(
                        binary_report,
                        "materialize_report_publication_committed_snapshot",
                        side_effect=[step4_snapshot, step5_snapshot],
                    ))
                    stack.enter_context(patch.object(
                        binary_report,
                        "_step4_publication_binding_matches_loaded",
                        return_value=step4_binding_matches,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_require_step5_snapshot_binding",
                        return_value=(
                            Path("/snapshot/call"),
                            Path("/snapshot/binary"),
                            Path("/snapshot/index"),
                        ),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_copy_step6_input_directory",
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_materialize_step6_upstream_evidence",
                        return_value=rebuilt_evidence_value,
                    ))
                    stack.enter_context(patch.object(
                        binary_report,
                        "_collect_step6_findings_for_publication",
                        return_value={},
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_bind_step6_findings_to_release",
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_write_step6_artifact_set",
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_validate_step6_deliverable_semantics",
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_directory_content_identity",
                        side_effect=identities,
                    ))
                    return binary_report._validate_step6_candidate_under_parent_workflow_lock(
                        report,
                        candidate_deliverables_dir=deliverables,
                        candidate_findings_dir=findings_dir,
                        candidate_publication_binding=binding_value,
                    )

        with patch.object(
            binary_report, "_report_workflow_read_lock",
            return_value=nullcontext(),
        ), patch.object(
            binary_report,
            "_validate_step6_candidate_under_parent_workflow_lock",
        ) as locked_validator:
            binary_report.validate_step6_publication_candidate(
                "/report",
                candidate_deliverables_dir="/candidate/deliverables",
                candidate_findings_dir="/candidate/findings",
                candidate_publication_binding={},
            )
        locked_validator.assert_called_once()

        self.assertIsNone(invoke())
        for binding in (
            None,
            {**expected_binding, "core": SHA_B},
            {**expected_binding, "publication_input_identity": SHA_B},
        ):
            with self.subTest(binding=binding):
                self.assert_reason(
                    "BINARY_STEP6_PUBLICATION_BINDING_MISMATCH",
                    lambda binding=binding: invoke(binding=binding),
                )

        self.assert_reason(
            "BINARY_STEP6_PUBLICATION_CANDIDATE_INCOMPLETE",
            lambda: invoke(missing_deliverable="report.md"),
        )
        self.assert_reason(
            "BINARY_STEP6_PUBLICATION_CANDIDATE_INCOMPLETE",
            lambda: invoke(findings_exists=False),
        )

        finding_mutations = (
            ("schema", "wrong"),
            ("authority", "source_first"),
            ("result_generation_identity", SHA_B),
            ("step4_publication_receipt_identity", "wrong-step4"),
            ("step5_publication_receipt_identity", "wrong-step5"),
            ("step6_publication_input_identity", SHA_B),
            ("step6_upstream_evidence_inputs", {}),
        )
        for field, value in finding_mutations:
            mutated = {**base_findings, field: value}
            with self.subTest(findings_field=field):
                self.assert_reason(
                    "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                    lambda mutated=mutated: invoke(findings=mutated),
                )
        self.assert_reason(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            lambda: invoke(findings={**base_findings, "generated_at": None}),
        )

        for binding_value, transaction_id in ((None, None), ({}, "step4-tx")):
            with self.subTest(step4_binding=binding_value):
                self.assert_reason(
                    "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
                    lambda binding_value=binding_value,
                    transaction_id=transaction_id: invoke(
                        step4_binding=binding_value,
                        step4_binding_matches=False,
                        step4_transaction_id=transaction_id,
                    ),
                )

        for sources, transaction_id in (
            (None, None), (["/snapshot/only"], "step4-tx"),
        ):
            with self.subTest(step4_sources=sources):
                self.assert_reason(
                    "BINARY_STEP4_PUBLICATION_SNAPSHOT_INVALID",
                    lambda sources=sources,
                    transaction_id=transaction_id: invoke(
                        step4_binding={"valid": SHA_A},
                        step4_sources=sources,
                        step4_transaction_id=transaction_id,
                    ),
                )

        self.assert_reason(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            lambda: invoke(rebuilt_upstream={}),
        )
        self.assert_reason(
            "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
            lambda: invoke(rebuilt_findings={}),
        )
        for identities in (
            [SHA_A, SHA_B],
            [SHA_A, SHA_A, SHA_A, SHA_B],
        ):
            with self.subTest(directory_identities=identities):
                self.assert_reason(
                    "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                    lambda identities=identities: invoke(
                        directory_identities=identities,
                    ),
                )

    def test_step5_snapshot_fact_fallback_selection_writer_and_cas_matrix(self):
        def api_item(
            coord, api, status, *, kind="method", facts=(),
            lookup_key=None, reported_identity="reported",
        ):
            return {
                "coord": coord,
                "api": api,
                "api_signature": "()",
                "symbol_kind": kind,
                "api_identity": f"identity:{api}",
                "reported_api_identity": reported_identity,
                "change_fact_identity": f"change:{api}",
                "decision_identity": f"decision:{api}",
                "change_type": "REMOVED",
                "analysis_status": status,
                "impact_conclusion": (
                    "probable_impact" if status == "reachable"
                    else "inconclusive"
                ),
                "contributing_change_fact_ids": list(facts),
                "lookup_key": lookup_key or (
                    coord, api, "()", kind,
                ),
            }

        rich_items = [
            api_item(
                "g:a", "Api.a", "reachable",
                facts=(None, "missing", "F1", "F1"),
            ),
            api_item("g:b", "Api.b", "uncertain", facts=("F2",)),
            api_item("g:c", "Api.c", "not_found_in_static_analysis"),
            api_item(
                "g:d", "Api.d", "not_analyzed",
                lookup_key=("g:d", "Api.d", "()", "method"),
            ),
            api_item(
                "g:e", "Api.e", "reachable",
                lookup_key=("g:e", "Api.e", "()", "method"),
            ),
            api_item("g:f", "Api.f", "uncertain"),
            api_item(
                "", "Api.unknown", "not_analyzed",
                reported_identity="",
            ),
        ]
        rich_resources = [
            {
                "coord": "g:r", "resource_name": "service-loader",
                "activation_status": "reachable",
                "business_entries": ["entry.Main"],
            },
            {
                "coord": "g:a", "resource_name": "configuration",
                "activation_status": None, "business_entries": [],
            },
            {
                "coord": "", "resource_name": "unbound",
                "activation_status": "not_analyzed",
                "business_entries": [],
            },
        ]
        projections = [
            {
                "decision_identity": "D1",
                "analysis_projection_status": "targetable",
            },
            {
                "decision_identity": "D2",
                "analysis_projection_status": "targetable",
            },
            {
                "decision_identity": "D3",
                "analysis_projection_status": "diagnostic_only",
            },
            {
                "decision_identity": None,
                "analysis_projection_status": "targetable",
            },
        ]
        decisions = [
            {
                "change_fact_identity": "F1", "decision_identity": "D1",
                "product": {"change_fact_identity": "F1"},
            },
            {
                "change_fact_identity": "F2", "decision_identity": "D2",
                "product": {},
            },
            {
                "change_fact_identity": "F3", "decision_identity": "D3",
                "product": {"change_fact_identity": "F3"},
            },
            {
                "change_fact_identity": None, "decision_identity": "D1",
                "product": {},
            },
            {
                "change_fact_identity": "F4", "decision_identity": None,
                "product": {"change_fact_identity": "F4"},
            },
        ]
        change_lookup = {
            ("g:c", "Api.c", "()", "method"): {"match": "exact"},
            ("g:d", "Api.d", "(int)", "method"): {"match": "kind"},
            ("g:e", "Api.e", "(int)", "field"): {"match": "broad"},
        }
        missing = object()

        def invoke(
            *, items=(), resources=(), projection_rows=(), decision_rows=(),
            lookup=None, selected_coords=(), selected_names=(),
            receipt=missing, output_matches=True, activation_identity=None,
            trace_complete=True, refreshed_matches=True,
            execute_writers=False, diagnostic_counts=(0, 0),
        ):
            receipt_value = (
                {
                    "committed_receipt_identity": SHA_A,
                    "transaction_id": "step4-tx",
                    "binding": {"step4": SHA_A},
                }
                if receipt is missing else receipt
            )
            loaded = {
                "formal": {
                    "by_api": list(items),
                    "resource_activation_results": list(resources),
                },
                "projections": {
                    "authoritative_projection_assessments": list(
                        projection_rows
                    ),
                },
                "decisions": {
                    "authoritative_change_facts": list(decision_rows),
                },
                "summary": {
                    "trace_coverage_status": (
                        "complete" if trace_complete else "partial"
                    ),
                    "trace_coverage_gaps": (
                        [] if trace_complete else ["budget"]
                    ),
                    "diagnostic_candidate_fact_count": diagnostic_counts[0],
                    "candidate_trace_result_count": diagnostic_counts[1],
                },
                "manifest": {
                    "result_generation_identity": SHA_A,
                    "analysis_context_identity": SHA_B,
                },
                "active": {
                    "validation_run_identity": SHA_B,
                    "validation_result_sha256": SHA_C,
                    "activation_identity": activation_identity,
                },
                "coverage": {},
                "binding_marker": "current",
            }
            refreshed = {
                **loaded,
                "binding_marker": (
                    "current" if refreshed_matches else "changed"
                ),
            }
            captured = {"json": [], "text": [], "staged": []}
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                report = root / "report"
                report.mkdir()
                output = report / "evidence" / "call_chain"
                requested_output = output if output_matches else report / "wrong"
                destinations = (
                    output,
                    report / "evidence" / "binary_analysis",
                    report / ".runtime" / "indexes",
                )

                def atomic_json(path, value):
                    captured["json"].append((Path(path).name, value))

                def atomic_text(path, value):
                    captured["text"].append((Path(path).name, value))

                def stage_group(entries, **_kwargs):
                    captured["staged"].extend(destination for destination, _ in entries)
                    if execute_writers:
                        for index, (_destination, writer) in enumerate(entries):
                            stage = root / f"stage-{index}"
                            stage.mkdir()
                            writer(stage, None)
                    return {"transaction_id": "step5-tx"}

                with ExitStack() as stack:
                    stack.enter_context(patch.object(
                        binary_report, "_source_inputs_view",
                        return_value={
                            "label": "source", "mapped_count": 0,
                            "coverage_status": "not_provided",
                            "effect": "no source mapping",
                        },
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_result_item", side_effect=lambda value: value,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_resource_activation_item",
                        side_effect=lambda value: value,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_change_rows_by_result",
                        return_value=([], dict(lookup or {})),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_product_change_row",
                        side_effect=lambda decision, *_args, **_kwargs: dict(
                            decision.get("product") or {}
                        ),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_change_row_key",
                        side_effect=lambda item: item["lookup_key"],
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_legacy_result_item",
                        side_effect=lambda item, _change: dict(item),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_step5_publication_input_identity",
                        return_value=SHA_C,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_step5_report_publication_destinations",
                        return_value=destinations,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_legacy_alert_rows",
                        side_effect=lambda values: [
                            {"path_status": item["analysis_status"]}
                            for item in values
                        ],
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_safe_detail_filename",
                        side_effect=lambda item: (
                            item["api"].replace(".", "-") + ".json"
                        ),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_atomic_json", side_effect=atomic_json,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_atomic_text", side_effect=atomic_text,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "derive_coverage_report", return_value={},
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_stage_directory_group",
                        side_effect=stage_group,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_active_generation_publication_lock",
                        return_value=nullcontext(),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "load_validated_generation",
                        return_value=refreshed,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_loaded_step4_publication_binding",
                        side_effect=lambda value: value["binding_marker"],
                    ))
                    stack.enter_context(patch.object(
                        binary_report,
                        "report_publication_committed_receipt",
                    ))
                    result = binary_report._publish_step5_from_snapshot(
                        report,
                        requested_output,
                        loaded=loaded,
                        step4_api_changes_dir=root / "step4-api",
                        step4_receipt=receipt_value,
                        selected_coords=selected_coords,
                        selected_names=selected_names,
                    )
                return result, captured

        result, captured = invoke(execute_writers=True)
        self.assertEqual(result["api_count"], 0)
        self.assertEqual(len(captured["staged"]), 3)

        result, captured = invoke(
            items=rich_items,
            resources=rich_resources,
            projection_rows=projections,
            decision_rows=decisions,
            lookup=change_lookup,
            activation_identity=SHA_A,
            trace_complete=False,
            execute_writers=True,
            diagnostic_counts=(2, 3),
        )
        self.assertEqual(result["api_count"], len(rich_items))
        summary_markdown = "\n".join(
            value for name, value in captured["text"]
            if name == "summary.md"
        )
        self.assertIn("未知", summary_markdown)
        self.assertIn("entry.Main", summary_markdown)

        result, _captured = invoke(
            items=rich_items,
            resources=rich_resources,
            projection_rows=projections,
            decision_rows=decisions,
            lookup=change_lookup,
            selected_coords=("", "g:a"),
            selected_names=("", "b"),
        )
        self.assertEqual(result["api_count"], 2)

        result, _captured = invoke(
            items=rich_items,
            resources=rich_resources,
            lookup=change_lookup,
            selected_names=("b",),
        )
        self.assertEqual(result["api_count"], 1)

        for coords, names in (
            (("g:missing",), ()),
            ((), ("missing",)),
        ):
            with self.subTest(selected_coords=coords, selected_names=names):
                self.assert_reason(
                    "BINARY_STEP5_SELECTION_UNMATCHED",
                    lambda coords=coords, names=names: invoke(
                        items=rich_items,
                        resources=rich_resources,
                        lookup=change_lookup,
                        selected_coords=coords,
                        selected_names=names,
                    ),
                )

        error = self.assert_reason(
            "BINARY_STEP4_PUBLICATION_RECEIPT_INVALID",
            lambda: invoke(receipt={"transaction_id": "visible-tx"}),
        )
        self.assertEqual(str(error), "visible-tx")
        empty_labels = {
            **rich_items[-1],
            "api": "",
            "symbol_kind": "",
            "lookup_key": ("", "", "()", ""),
        }
        error = self.assert_reason(
            "BINARY_STEP4_PUBLICATION_RECEIPT_INVALID",
            lambda: invoke(items=(empty_labels,), receipt={}),
        )
        self.assertEqual(str(error), "")
        self.assert_reason(
            "BINARY_STEP5_PUBLICATION_TARGET_INVALID",
            lambda: invoke(output_matches=False),
        )
        self.assert_reason(
            "BINARY_STEP5_ACTIVE_GENERATION_CHANGED",
            lambda: invoke(refreshed_matches=False),
        )

    def test_step4_projection_metrics_source_writer_and_activation_matrix(self):
        def product_row(index, *, severity="P2"):
            return {
                "coord": f"g:artifact-{index}",
                "api_name": f"p.Api{index}.m",
                "api_signature": "()",
                "change_type": "REMOVED",
                "symbol_kind": "method",
                "severity": severity,
                "conclusion": "binary change",
                "_change_fact_identity": f"fact-{index}",
            }

        decisions = [
            {
                "decision_identity": f"decision-{index}",
                "row": product_row(
                    index, severity="P0" if index == 0 else "P2",
                ),
            }
            for index in range(11)
        ]
        decisions.extend((
            {
                "decision_identity": None,
                "row": product_row(11),
            },
            {
                "decision_identity": "diagnostic-only",
                "row": product_row(12),
            },
        ))
        assessments = [
            {
                "decision_identity": decision["decision_identity"],
                "analysis_projection_status": (
                    "diagnostic_only"
                    if decision["decision_identity"] == "diagnostic-only"
                    else "targetable"
                ),
            }
            for decision in decisions
        ]
        metrics = {
            "fact-0": {
                "exact_api": True, "possible_api": True,
                "exact_paths": 2, "possible_paths": 3,
            },
            "fact-1": {
                "exact_api": False, "possible_api": True,
                "exact_paths": 0, "possible_paths": 1,
            },
            "fact-2": {
                "exact_api": False, "possible_api": False,
                "exact_paths": None, "possible_paths": None,
            },
        }
        source_review_rows = [
            {
                "源码归属": "g:artifact-0", "归属类型": "dependency",
                "二进制制品": "artifact.jar", "二进制方法": "p.Api0.m()",
                "源码位置": "src/Api0.java:1", "模块": "root",
                "语言": "java", "源码声明": "", "注解": "",
                "修饰符": "public",
            },
            {
                "源码归属": "g:artifact-1", "归属类型": "dependency",
                "二进制制品": "artifact.jar", "二进制方法": "p.Api1.m()",
                "源码位置": "src/Api1.kt:1", "模块": "root",
                "语言": "kotlin", "源码声明": "fun m()",
                "注解": "@JvmStatic", "修饰符": "public",
            },
        ]
        source_candidate_rows = [{
            "源码归属": "g:artifact-0", "二进制制品": "artifact.jar",
            "调用方": "p.Caller.call()", "源码位置": "src/Caller.java:1",
            "候选目标": "p.Api0.m()", "证据类型": "source_candidate",
            "置信度": "candidate", "权威边界": "not_formal",
        }]
        rich_source_inputs = {
            "label": "source provided",
            "mapped_count": 2,
            "coverage_status": "partial",
            "effect": "source is explanatory",
            "language_file_counts": {"java": 1, "kotlin": 1},
            "coverage_gaps": [
                {
                    "reason_code": "BINARY_SOURCE_LANGUAGE_NOT_MAPPED",
                    "language": "scala", "owner_coord": "g:scala",
                    "module": "root", "logical_path": "A.scala",
                    "actual_parser": "none", "error_nodes": 2,
                },
                {
                    "reason_code": "BINARY_SOURCE_PARSE_INCOMPLETE",
                    "language": None, "owner_coord": None, "module": None,
                    "logical_path": None, "actual_parser": None,
                    "error_nodes": None,
                },
            ],
        }

        def invoke(
            *, decision_rows=(), projection_rows=(), diagnostic_rows=(),
            trace_metrics=None, source_inputs=None, review_rows=(),
            candidate_rows=(), output_matches=True,
            activation_identity=None, trace_complete=True,
            execute_writer=False, confirmed_unprojectable=("unprojectable",),
            excluded_decisions=("excluded",),
        ):
            source_inputs_value = source_inputs or {
                "label": "not provided", "mapped_count": 0,
                "coverage_status": "not_provided",
                "effect": "binary conclusions remain authoritative",
                "language_file_counts": {}, "coverage_gaps": [],
            }
            captured = {"json": [], "text": [], "binding": None}
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                report = root / "report"
                report.mkdir()
                generation = report / ".runtime" / "generation"
                generation.mkdir(parents=True)
                output = report / "evidence" / "api_changes"
                requested_output = output if output_matches else report / "wrong"
                loaded = {
                    "decisions": {
                        "authoritative_change_facts": list(decision_rows),
                        "diagnostic_candidate_facts": list(diagnostic_rows),
                        "excluded_decisions": excluded_decisions,
                    },
                    "projections": {
                        "authoritative_projection_assessments": list(
                            projection_rows
                        ),
                        "confirmed_unprojectable_facts": (
                            confirmed_unprojectable
                        ),
                    },
                    "generation": generation,
                    "report_dir": report,
                    "summary": {
                        "trace_coverage_status": (
                            "complete" if trace_complete else "partial"
                        ),
                        "decision_coverage_status": "complete",
                    },
                    "coverage": {
                        "trace_coverage_gaps": (
                            [] if trace_complete else ["trace-budget"]
                        ),
                    },
                    "manifest": {
                        "result_generation_identity": SHA_A,
                        "analysis_context_identity": SHA_B,
                    },
                    "active": {
                        "validation_run_identity": SHA_B,
                        "validation_result_sha256": SHA_C,
                        "activation_identity": activation_identity,
                    },
                    "source_attestation": {"snapshot": True},
                }

                def review_row(decision, _assessment, *, conclusion):
                    identity = str(decision.get("decision_identity") or "")
                    return {
                        "依赖包": decision.get("row", {}).get(
                            "coord", "g:diagnostic"
                        ),
                        "变化对象": identity or "unidentified",
                        "升级前制品": "base.jar",
                        "升级后制品": "current.jar",
                        "变化类型": "REMOVED",
                        "裁决结论": conclusion,
                        "裁决原因": "binary fact",
                        "投影状态": "targetable",
                        "覆盖状态": "complete",
                        "需人工复核": "false",
                        "证据缺口": "",
                        "decision_identity": identity,
                    }

                def atomic_json(path, value):
                    captured["json"].append((Path(path).name, value))

                def atomic_text(path, value):
                    captured["text"].append((Path(path).name, value))

                def stage_group(entries, **kwargs):
                    captured["binding"] = kwargs["transaction_binding"]
                    if execute_writer:
                        first_destination, first_writer = tuple(entries)[0]
                        self.assertEqual(first_destination, output)
                        stage = root / "step4-stage"
                        stage.mkdir()
                        first_writer(stage, {})
                    return {"transaction_id": "step4-tx"}

                with ExitStack() as stack:
                    stack.enter_context(patch.object(
                        binary_report, "_ensure_publication_protocol_marker",
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "load_validated_generation",
                        return_value=loaded,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_source_inputs_view",
                        return_value=source_inputs_value,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_source_review_rows",
                        return_value=list(review_rows),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_source_candidate_review_rows",
                        return_value=list(candidate_rows),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_product_change_row",
                        side_effect=lambda decision, *_args, **_kwargs: dict(
                            decision["row"]
                        ),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_review_row", side_effect=review_row,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_trace_metrics_by_change",
                        return_value=dict(trace_metrics or {}),
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_atomic_json", side_effect=atomic_json,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_atomic_text", side_effect=atomic_text,
                    ))
                    stack.enter_context(patch.object(
                        binary_report, "_stage_directory_group",
                        side_effect=stage_group,
                    ))
                    result = binary_report._publish_step4_with_lock(
                        report,
                        requested_output,
                        candidate_activation_identity="candidate",
                    )
                return result, captured

        result, captured = invoke(
            execute_writer=True,
            confirmed_unprojectable=None,
            excluded_decisions=None,
        )
        self.assertEqual(result["change_fact_count"], 0)
        self.assertNotIn("activation_identity", captured["binding"])
        empty_markdown = "\n".join(value for _name, value in captured["text"])
        self.assertIn("没有可用源码输入", empty_markdown)

        result, captured = invoke(
            decision_rows=decisions,
            projection_rows=assessments,
            diagnostic_rows=({"decision_identity": "candidate"},),
            trace_metrics=metrics,
            source_inputs=rich_source_inputs,
            review_rows=source_review_rows,
            candidate_rows=source_candidate_rows,
            activation_identity=SHA_A,
            trace_complete=False,
            execute_writer=True,
        )
        self.assertEqual(result["change_fact_count"], 12)
        self.assertEqual(captured["binding"]["activation_identity"], SHA_A)
        rich_markdown = "\n".join(value for _name, value in captured["text"])
        self.assertIn("Top 10", rich_markdown)
        self.assertIn("fun m()", rich_markdown)
        self.assertIn("源码候选关系", rich_markdown)

        provided_without_mapping = {
            **rich_source_inputs,
            "mapped_count": 0,
            "language_file_counts": {},
            "coverage_gaps": [],
        }
        _result, captured = invoke(
            decision_rows=(decisions[0],),
            projection_rows=(assessments[0],),
            source_inputs=provided_without_mapping,
            execute_writer=True,
        )
        provided_markdown = "\n".join(
            value for _name, value in captured["text"]
        )
        self.assertIn("没有方法完成精确 descriptor 映射", provided_markdown)

        self.assert_reason(
            "BINARY_STEP4_PUBLICATION_TARGET_INVALID",
            lambda: invoke(output_matches=False),
        )

    def test_cli_phase_arguments_prepare_rejection_results_and_failure_matrix(self):
        invalid_argument_sets = (
            [
                "--phase", "step4", "--report-dir", "/report",
                "--candidate-activation-identity", SHA_A,
            ],
            [
                "--phase", "step5", "--report-dir", "/report",
                "--prepare-publication-candidate",
                "--candidate-activation-identity", SHA_A,
            ],
            ["--phase", "step4", "--report-dir", "/report"],
            ["--phase", "step5", "--report-dir", "/report"],
            ["--phase", "step6", "--report-dir", "/report"],
            [
                "--phase", "step6", "--report-dir", "/report",
                "--output-findings", "/findings.json",
            ],
        )
        for argv in invalid_argument_sets:
            with self.subTest(argv=argv), patch.object(
                binary_report.sys, "stderr", io.StringIO(),
            ):
                with self.assertRaises(SystemExit) as raised:
                    binary_report.main(argv)
                self.assertEqual(raised.exception.code, 2)

        with patch("builtins.print"), self.assertRaises(
            binary_report.BinaryReportError,
        ) as forbidden:
            binary_report.main([
                "--phase", "step4", "--report-dir", "/report",
                "--prepare-publication-candidate",
                "--candidate-activation-identity", SHA_A,
            ])
        self.assertEqual(
            forbidden.exception.reason_code,
            "BINARY_REPORT_PREPARE_CLI_FORBIDDEN",
        )

        written = []
        with patch.object(
            binary_report, "publish_step4", return_value={"phase": "step4"},
        ) as step4, patch.object(
            binary_report, "publish_step5", return_value={"phase": "step5"},
        ) as step5, patch.object(
            binary_report, "publish_step6", return_value={"phase": "step6"},
        ) as step6, patch.object(
            binary_report, "_atomic_json",
            side_effect=lambda path, value: written.append((Path(path), value)),
        ), patch("builtins.print"):
            self.assertEqual(binary_report.main([
                "--phase", "step4", "--report-dir", "/report",
                "--output-dir", "/step4",
            ]), 0)
            self.assertEqual(binary_report.main([
                "--phase", "step5", "--report-dir", "/report",
                "--output-dir", "/step5",
                "--selected-coord", "g:a",
                "--selected-name", "a",
                "--result-json", "/step5-result.json",
            ]), 0)
            self.assertEqual(binary_report.main([
                "--phase", "step6", "--report-dir", "/report",
                "--output-findings", "/findings.json",
                "--output-report", "/report.md",
            ]), 0)
        step4.assert_called_once_with("/report", "/step4")
        step5.assert_called_once_with(
            "/report", "/step5",
            selected_coords=("g:a",), selected_names=("a",),
        )
        step6.assert_called_once_with(
            "/report", "/findings.json", "/report.md",
        )
        self.assertEqual(written[0][0], Path("/step5-result.json"))

        for result_json in (None, "/failure.json"):
            failure = binary_report.BinaryReportError(
                "BINARY_STEP4_PUBLICATION_TARGET_INVALID", "bad output",
            )
            argv = [
                "--phase", "step4", "--report-dir", "/report",
                "--output-dir", "/wrong",
            ]
            if result_json:
                argv.extend(("--result-json", result_json))
            writes = []
            with self.subTest(result_json=result_json), patch.object(
                binary_report, "publish_step4", side_effect=failure,
            ), patch.object(
                binary_report, "_atomic_json",
                side_effect=lambda path, value: writes.append((path, value)),
            ), patch("builtins.print"):
                with self.assertRaises(binary_report.BinaryReportError):
                    binary_report.main(argv)
            self.assertEqual(bool(writes), bool(result_json))

    def test_step4_verification_empty_transaction_error_details(self):
        report = Path("/virtual/report")
        loaded = {
            "manifest": {
                "result_generation_identity": SHA_A,
                "analysis_context_identity": SHA_B,
            },
            "active": {},
        }

        with patch.object(
            binary_report, "load_validated_generation", return_value=loaded,
        ), patch.object(
            binary_report,
            "materialize_report_publication_committed_snapshot",
            return_value={"binding": {}, "transaction_id": None},
        ), patch.object(
            binary_report,
            "_step4_publication_binding_matches_loaded",
            return_value=False,
        ):
            error = self.assert_reason(
                "BINARY_STEP4_PUBLICATION_BINDING_MISMATCH",
                lambda: binary_report.verify_current_step4_release(
                    report,
                    workflow_lock_held=True,
                    active_lock_held=True,
                ),
            )
        self.assertEqual(str(error), "")

        snapshot = {
            "binding": {},
            "transaction_id": None,
            "gate_receipt": {},
            "snapshot_destinations": [
                "/virtual/api", "/virtual/source",
            ],
            "committed_receipt_identity": SHA_A,
        }
        summary = {
            "schema": "java-upgrade-analyzer.binary-step4-summary.v1",
            "authority": "binary_first",
            "result_generation_identity": SHA_A,
            "analysis_context_identity": SHA_B,
        }
        with patch.object(
            binary_report, "load_validated_generation", return_value=loaded,
        ), patch.object(
            binary_report,
            "materialize_report_publication_committed_snapshot",
            return_value=snapshot,
        ), patch.object(
            binary_report,
            "_step4_publication_binding_matches_loaded",
            return_value=True,
        ), patch.object(
            binary_report, "_load_json", return_value=summary,
        ), patch.object(
            binary_report,
            "require_current_release_stage",
            return_value={
                "step4": {"committed_receipt_identity": SHA_B},
            },
        ):
            error = self.assert_reason(
                "BINARY_GLOBAL_RELEASE_STEP4_RECEIPT_MISMATCH",
                lambda: binary_report.verify_current_step4_release(
                    report,
                    workflow_lock_held=True,
                    active_lock_held=True,
                ),
            )
        self.assertEqual(str(error), "")

    def test_evidence_path_owner_and_required_file_boundaries(self):
        self.assertEqual(
            binary_report._normalized_step6_upstream_evidence_path(
                "evidence/static_scan/./custom.csv"
            ),
            "evidence/static_scan/custom.csv",
        )
        self.assertIsNone(binary_report.step6_internal_input_owner_for_path(None))
        self.assertIsNone(binary_report._step6_internal_input_diagnostic_owner({}))

        failures = binary_report.step6_internal_input_contract_failures({
            "diagnostics": [{
                "owner_step": "step1",
                "stage": "json_contract",
                "artifact": None,
                "error_type": "ValueError",
                "path": "",
                "message": "invalid",
            }],
        })
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["artifact"], "")
        self.assertEqual(failures[0]["stage"], "json_contract")

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory).resolve()
            inventory = (
                report / "evidence/dependencies/deps_current_resolved.csv"
            )
            inventory.parent.mkdir(parents=True)
            inventory.write_text("coord\n", encoding="utf-8")
            required = binary_report._required_step6_upstream_evidence_files(
                report, context={},
            )
        self.assertIn(
            "evidence/static_scan/s3_dependency_compat.csv", required,
        )
        self.assertIn(
            "evidence/static_scan/s3_dependency_classfile.csv", required,
        )

    def test_step6_evidence_materialization_classifies_parent_and_leaf_failures(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        report = root / "report"
        render = root / "render"
        relative = "evidence/static_scan/custom.csv"

        leaf_error = binary_report.BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", "leaf",
        )
        leaf_error.unsafe_parent_path = False
        with patch.object(
            binary_report,
            "_step6_upstream_evidence_files",
            return_value={relative},
        ), patch.object(
            binary_report, "_publication_path_exists", return_value=True,
        ), patch.object(
            binary_report,
            "_require_step6_upstream_regular_file",
            side_effect=[leaf_error, report / relative],
        ), patch.object(
            binary_report, "_append_step6_internal_input_diagnostic",
        ) as append, patch.object(
            binary_report, "_copy_report_file_secure",
        ), patch.object(
            binary_report,
            "_step6_upstream_evidence_state",
            return_value={relative: {"status": "present"}},
        ):
            state = binary_report._materialize_step6_upstream_evidence(
                report, render, require_complete=False,
            )
        self.assertEqual(state[relative]["status"], "present")
        append.assert_called_once()

        parent_error = binary_report.BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", "parent",
        )
        parent_error.unsafe_parent_path = True
        with patch.object(
            binary_report,
            "_step6_upstream_evidence_files",
            return_value={relative},
        ), patch.object(
            binary_report, "_publication_path_exists", return_value=True,
        ), patch.object(
            binary_report,
            "_require_step6_upstream_regular_file",
            side_effect=parent_error,
        ):
            with self.assertRaises(binary_report.BinaryReportError):
                binary_report._materialize_step6_upstream_evidence(
                    report, render, require_complete=False,
                )

    def test_step6_evidence_state_preflight_parent_and_leaf_failure_matrix(self):
        report = Path("/virtual/report")
        relative = "evidence/static_scan/custom.csv"

        leaf_error = binary_report.BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", "leaf",
        )
        leaf_error.unsafe_parent_path = False

        def augment(_root, findings):
            findings["diagnostics"].extend([
                "malformed-diagnostic",
                {}, {"artifact": None}, {"artifact": "other"},
            ])

        def exists(path):
            return Path(path) == report / relative

        with patch.object(
            binary_report,
            "_step6_upstream_evidence_files",
            return_value={relative},
        ), patch.object(
            binary_report,
            "_augment_step6_internal_input_diagnostics",
            side_effect=augment,
        ), patch.object(
            binary_report, "_publication_path_exists", side_effect=exists,
        ), patch.object(
            binary_report,
            "_require_step6_upstream_regular_file",
            side_effect=[leaf_error, report / relative],
        ), patch.object(
            binary_report,
            "_required_step6_upstream_evidence_files",
            return_value=set(),
        ), patch.object(
            binary_report, "_raise_step6_internal_input_failure",
        ), patch.object(
            binary_report, "_report_file_sha256", return_value=SHA_A,
        ):
            state = binary_report._step6_upstream_evidence_state(
                report, require_complete=True,
            )
        self.assertEqual(state[relative], {
            "status": "present", "content_identity": SHA_A,
        })

        def mark_context_invalid(_root, findings):
            findings["diagnostics"].append({"artifact": "context"})

        with patch.object(
            binary_report,
            "_step6_upstream_evidence_files",
            return_value=set(),
        ), patch.object(
            binary_report,
            "_augment_step6_internal_input_diagnostics",
            side_effect=mark_context_invalid,
        ), patch.object(
            binary_report,
            "_publication_path_exists",
            return_value=True,
        ), patch.object(
            binary_report,
            "_required_step6_upstream_evidence_files",
            return_value=set(),
        ), patch.object(
            binary_report, "_raise_step6_internal_input_failure",
        ), patch.object(binary_report, "_load_json") as load_context:
            self.assertEqual(
                binary_report._step6_upstream_evidence_state(
                    report, require_complete=True,
                ),
                {},
            )
        load_context.assert_not_called()

        parent_error = binary_report.BinaryReportError(
            "BINARY_REPORT_PUBLICATION_CONTENT_INVALID", "parent",
        )
        parent_error.unsafe_parent_path = True
        with patch.object(
            binary_report,
            "_step6_upstream_evidence_files",
            return_value={relative},
        ), patch.object(
            binary_report,
            "_augment_step6_internal_input_diagnostics",
        ), patch.object(
            binary_report, "_publication_path_exists", return_value=True,
        ), patch.object(
            binary_report,
            "_require_step6_upstream_regular_file",
            side_effect=parent_error,
        ):
            with self.assertRaises(binary_report.BinaryReportError):
                binary_report._step6_upstream_evidence_state(
                    report, require_complete=True,
                )

    def test_step6_writer_optional_detail_and_csv_shapes(self):
        findings = {"artifacts": {}}
        api_model = {
            "total_count": 0,
            "completed_count": 0,
            "incomplete_count": 0,
            "population_unconfirmed": False,
        }
        dependency_model = dict(api_model)
        with tempfile.TemporaryDirectory() as directory, patch.object(
            binary_report.s6_report,
            "cleanup_legacy_s6_detail_artifacts",
        ), patch.object(
            binary_report.s6_report,
            "write_changed_api_split_artifacts",
            return_value={},
        ), patch.object(
            binary_report.s6_report,
            "write_analysis_scope_artifact",
            return_value="scope.md",
        ), patch.object(
            binary_report.s6_report,
            "write_diagnostic_detail_artifact",
            return_value="",
        ), patch.object(
            binary_report.s6_report,
            "write_primary_report_artifacts",
            return_value=({}, api_model, dependency_model),
        ), patch.object(
            binary_report.s6_report, "generate_report", return_value="report",
        ), patch.object(binary_report, "_atomic_json"), patch.object(
            binary_report, "_atomic_text",
        ):
            binary_report._write_step6_artifact_set(
                Path(directory).resolve(), findings,
            )
        self.assertNotIn("diagnostic_detail_md", findings["artifacts"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            empty = root / "empty.csv"
            empty.write_text("", encoding="utf-8")
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: binary_report._read_step6_contract_csv(empty, ("a",)),
            )

            extra = root / "extra.csv"
            extra.write_text("a\n1,2\n", encoding="utf-8")
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: binary_report._read_step6_contract_csv(extra, ("a",)),
            )

            missing = root / "missing.csv"
            missing.write_text("a,b\n1\n", encoding="utf-8")
            self.assert_reason(
                "BINARY_STEP6_PUBLICATION_CONTENT_MISMATCH",
                lambda: binary_report._read_step6_contract_csv(
                    missing, ("a", "b"),
                ),
            )

    def test_step6_findings_release_binding_empty_and_populated_dimensions(self):
        base_loaded = {
            "manifest": {
                "result_generation_identity": SHA_A,
                "analysis_context_identity": SHA_B,
            },
            "formal": {
                "by_api": None,
                "resource_activation_results": None,
            },
            "generation": Path("/generation"),
        }
        empty_findings = {"analysis_scope": None}
        with patch.object(binary_report, "_source_inputs_view", return_value={}):
            binary_report._bind_step6_findings_to_release(
                empty_findings,
                loaded=base_loaded,
                step4_receipt={"committed_receipt_identity": SHA_A},
                step5_receipt={"committed_receipt_identity": SHA_B},
                step6_input_identity=SHA_C,
                upstream_evidence_inputs={},
            )
        self.assertEqual(empty_findings["resource_impacts"], [])
        self.assertEqual(
            sum(empty_findings["binary_dimensions"]["reachability_status"].values()),
            0,
        )

        rows = [
            {
                "reported_api_identity": "api-1",
                "reachability_status": "reachable",
                "impact_conclusion": "probable_impact",
            },
            {
                "reported_api_identity": "api-2",
                "reachability_status": "uncertain",
                "impact_conclusion": "inconclusive",
            },
            {
                "reported_api_identity": None,
                "reachability_status": "not_found_in_static_analysis",
                "impact_conclusion": "inconclusive",
            },
            {
                "reported_api_identity": "api-4",
                "reachability_status": "not_analyzed",
                "impact_conclusion": "inconclusive",
            },
        ]
        loaded = {
            **base_loaded,
            "formal": {
                "by_api": rows,
                "resource_activation_results": [
                    {"coord": None}, {"coord": "g:a"}, {"coord": "g:b"},
                ],
            },
        }
        findings = {
            "analysis_scope": {
                "included_reported_api_identities": [
                    None, " ", "api-1", "api-2",
                ],
                "included_dependency_coords": [
                    None, " ", "g:a",
                ],
            },
        }
        with patch.object(
            binary_report, "_source_inputs_view", return_value={},
        ), patch.object(
            binary_report,
            "_resource_activation_item",
            side_effect=lambda item: dict(item),
        ):
            binary_report._bind_step6_findings_to_release(
                findings,
                loaded=loaded,
                step4_receipt={"committed_receipt_identity": SHA_A},
                step5_receipt={"committed_receipt_identity": SHA_B},
                step6_input_identity=SHA_C,
                upstream_evidence_inputs={"input": {"status": "present"}},
            )
        self.assertEqual(
            [item["coord"] for item in findings["resource_impacts"]],
            ["g:a"],
        )
        self.assertEqual(
            findings["binary_dimensions"]["reachability_status"],
            {
                "reachable": 1,
                "uncertain": 1,
                "not_found_in_static_analysis": 0,
                "not_analyzed": 0,
            },
        )
        self.assertEqual(
            findings["generation_binary_dimensions"]["reachability_status"],
            {
                "reachable": 1,
                "uncertain": 1,
                "not_found_in_static_analysis": 1,
                "not_analyzed": 1,
            },
        )
        self.assertEqual(
            findings["binary_dimensions"]["impact_conclusion"],
            {"probable_impact": 1, "inconclusive": 1},
        )

    def test_publication_failure_allows_missing_reason_code(self):
        error = binary_report.BinaryReportError("TEMPORARY", "failure")
        error.reason_code = ""
        result = binary_report.binary_report_publication_failure_result(
            error, phase="step6",
        )
        self.assertEqual(result["reason_code"], "")
        self.assertEqual(result["phase"], "step6")


if __name__ == "__main__":
    unittest.main()
