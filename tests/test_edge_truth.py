import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import edge_truth  # noqa: E402


VALID_ARTIFACT_ENTRIES = {"BOOT-INF/classes/p/C.class"}


def edge(
    artifact_sha256,
    caller_owner,
    caller_member,
    caller_descriptor,
    callee_owner,
    callee_member,
    callee_descriptor,
    opcode_family,
    *,
    artifact_entry="BOOT-INF/classes/p/C.class",
    authority="jdk-javap",
    authority_version="21.0.2",
    procedure="javap -c -s -p <class-file>",
    edge_state=None,
    present=None,
):
    row = {
        "artifact_sha256": artifact_sha256,
        "artifact_entry": artifact_entry,
        "caller_owner": caller_owner,
        "caller_member": caller_member,
        "caller_descriptor": caller_descriptor,
        "callee_owner": callee_owner,
        "callee_member": callee_member,
        "callee_descriptor": callee_descriptor,
        "opcode_family": opcode_family,
        "authority": authority,
        "authority_version": authority_version,
        "procedure": procedure,
    }
    if edge_state is not None:
        row["edge_state"] = edge_state
    if present is not None:
        row["present"] = present
    return row


def valid_edge(
    member,
    *,
    artifact_sha256=None,
    caller_descriptor="()V",
    callee_descriptor="()V",
    opcode_family="invokevirtual",
    artifact_entry="BOOT-INF/classes/p/C.class",
    edge_state=None,
    present=None,
    authority="jdk-javap",
):
    return edge(
        artifact_sha256 or "a" * 64,
        "p.C",
        member,
        caller_descriptor,
        "q.Api",
        "run",
        callee_descriptor,
        opcode_family,
        artifact_entry=artifact_entry,
        authority=authority,
        edge_state=edge_state,
        present=present,
    )


def invalid_edge():
    return edge(
        "a" * 63 + "Z",
        "p.C",
        "run",
        "()V",
        "q.Api",
        "run",
        "()V",
        "invokevirtual",
        artifact_entry="",
    )


class EdgeTruthTest(unittest.TestCase):
    def test_descriptor_and_opcode_are_part_of_edge_identity(self):
        base = edge("a" * 64, "p.C", "call", "()V", "q.Api", "run", "()V", "invokevirtual")
        overload = {**base, "callee_descriptor": "(I)V"}
        interface = {**base, "opcode_family": "invokeinterface"}

        self.assertNotEqual(edge_truth.canonical_edge_identity(base), edge_truth.canonical_edge_identity(overload))
        self.assertNotEqual(edge_truth.canonical_edge_identity(base), edge_truth.canonical_edge_identity(interface))

    def test_reconciliation_reports_missing_extra_and_invalid_provenance(self):
        result = edge_truth.reconcile_edges(
            [valid_edge("run")],
            [valid_edge("other"), invalid_edge()],
            trusted_artifact_sha="a" * 64,
            valid_artifact_entries=VALID_ARTIFACT_ENTRIES,
        )

        self.assertEqual(result["verdict_counts"]["missing"], 1)
        self.assertEqual(result["verdict_counts"]["extra"], 1)
        self.assertEqual(result["verdict_counts"]["provenance_invalid"], 1)
        self.assertTrue(result["blocking"])

    def test_same_names_but_different_descriptor_or_opcode_are_identity_mismatch(self):
        analyzer = [valid_edge("run")]
        oracle = [{**valid_edge("run"), "callee_descriptor": "(I)V", "opcode_family": "invokeinterface"}]

        result = edge_truth.reconcile_edges(
            analyzer,
            oracle,
            trusted_artifact_sha="a" * 64,
            valid_artifact_entries=VALID_ARTIFACT_ENTRIES,
        )

        self.assertEqual(result["verdict_counts"]["identity_mismatch"], 2)
        self.assertEqual(result["verdict_counts"]["missing"], 0)
        self.assertEqual(result["verdict_counts"]["extra"], 0)
        self.assertTrue(result["blocking"])

    def test_duplicate_rows_are_counted_as_a_multiset(self):
        analyzer = [valid_edge("run"), valid_edge("run")]
        oracle = [valid_edge("run")]

        result = edge_truth.reconcile_edges(
            analyzer,
            oracle,
            trusted_artifact_sha="a" * 64,
            valid_artifact_entries=VALID_ARTIFACT_ENTRIES,
        )

        self.assertEqual(result["verdict_counts"]["correct"], 2)
        self.assertEqual(result["verdict_counts"]["extra"], 1)
        self.assertEqual(len(result["ledger"]), 3)
        self.assertTrue(result["blocking"])

    def test_conflicting_truth_state_ledgers_every_row(self):
        analyzer = [valid_edge("run")]
        oracle = [
            valid_edge("run", edge_state="present"),
            valid_edge("run", edge_state="absent", authority="independent-review"),
        ]

        result = edge_truth.reconcile_edges(
            analyzer,
            oracle,
            trusted_artifact_sha="a" * 64,
            valid_artifact_entries=VALID_ARTIFACT_ENTRIES,
        )

        self.assertEqual(result["verdict_counts"]["oracle_conflict"], 3)
        self.assertEqual(len(result["ledger"]), 3)
        self.assertTrue(all(row["verdict"] == "oracle_conflict" for row in result["ledger"]))
        self.assertTrue(result["blocking"])

    def test_artifact_entry_mismatch_marks_analyzer_invalid(self):
        analyzer = [valid_edge("run", artifact_entry="BOOT-INF/classes/p/Other.class")]
        oracle = [valid_edge("run")]

        result = edge_truth.reconcile_edges(
            analyzer,
            oracle,
            trusted_artifact_sha="a" * 64,
            valid_artifact_entries=VALID_ARTIFACT_ENTRIES,
        )

        self.assertEqual(result["verdict_counts"]["provenance_invalid"], 1)
        self.assertEqual(result["verdict_counts"]["missing"], 1)
        self.assertFalse(result["verdict_counts"]["identity_mismatch"])
        self.assertTrue(result["blocking"])

    def test_wrong_valid_sha_is_provenance_invalid_not_identity_mismatch(self):
        analyzer = [valid_edge("run", artifact_sha256="b" * 64)]
        oracle = [valid_edge("run")]

        result = edge_truth.reconcile_edges(
            analyzer,
            oracle,
            trusted_artifact_sha="a" * 64,
            valid_artifact_entries=VALID_ARTIFACT_ENTRIES,
        )

        self.assertEqual(result["verdict_counts"]["provenance_invalid"], 1)
        self.assertEqual(result["verdict_counts"]["missing"], 1)
        self.assertEqual(result["verdict_counts"]["identity_mismatch"], 0)
        self.assertTrue(result["blocking"])

    def test_fabricated_sha_and_entry_rows_are_ledgered_as_provenance_invalid(self):
        analyzer = [valid_edge("run", artifact_sha256="b" * 64, artifact_entry="BOOT-INF/classes/p/C.class")]
        oracle = [valid_edge("run", artifact_entry="BOOT-INF/classes/p/Other.class")]

        result = edge_truth.reconcile_edges(
            analyzer,
            oracle,
            trusted_artifact_sha="a" * 64,
            valid_artifact_entries=VALID_ARTIFACT_ENTRIES,
        )

        self.assertEqual(result["verdict_counts"]["provenance_invalid"], 2)
        self.assertEqual(result["verdict_counts"]["correct"], 0)
        self.assertEqual(len(result["ledger"]), 2)
        self.assertTrue(all(row["verdict"] == "provenance_invalid" for row in result["ledger"]))
        self.assertTrue(result["blocking"])

    def test_present_vs_absent_same_identity_is_oracle_conflict(self):
        analyzer = [valid_edge("run", edge_state="present")]
        oracle = [valid_edge("run", edge_state="absent")]

        result = edge_truth.reconcile_edges(
            analyzer,
            oracle,
            trusted_artifact_sha="a" * 64,
            valid_artifact_entries=VALID_ARTIFACT_ENTRIES,
        )

        self.assertEqual(result["verdict_counts"]["oracle_conflict"], 2)
        self.assertEqual(result["verdict_counts"]["correct"], 0)
        self.assertEqual(len(result["ledger"]), 2)
        self.assertTrue(all(row["verdict"] == "oracle_conflict" for row in result["ledger"]))
        self.assertTrue(result["blocking"])

    def test_omitting_valid_artifact_entries_raises_type_error(self):
        with self.assertRaises(TypeError):
            edge_truth.reconcile_edges(
                [valid_edge("run")],
                [valid_edge("run")],
                trusted_artifact_sha="a" * 64,
            )

    def test_empty_valid_artifact_entries_raises_value_error(self):
        with self.assertRaises(ValueError):
            edge_truth.reconcile_edges(
                [valid_edge("run")],
                [valid_edge("run")],
                trusted_artifact_sha="a" * 64,
                valid_artifact_entries=set(),
            )


if __name__ == "__main__":
    unittest.main()
