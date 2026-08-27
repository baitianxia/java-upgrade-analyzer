from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import binary_validation_oracle as oracle
from binary_fact_store import BinaryFactStore


def _fact_connection(database: str | Path = ":memory:") -> sqlite3.Connection:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE members (
            member_identity TEXT PRIMARY KEY,
            artifact_instance_identity TEXT NOT NULL,
            class_name TEXT NOT NULL,
            member_name TEXT NOT NULL,
            descriptor TEXT NOT NULL
        );
        CREATE TABLE direct_edges (
            caller_member_identity TEXT NOT NULL,
            caller_artifact_instance_identity TEXT NOT NULL,
            edge_kind TEXT NOT NULL,
            symbolic_owner TEXT NOT NULL,
            symbolic_name TEXT NOT NULL,
            symbolic_descriptor TEXT NOT NULL,
            opcode INTEGER NOT NULL,
            bytecode_offset INTEGER NOT NULL,
            edge_json TEXT NOT NULL
        );
        CREATE INDEX direct_edges_by_artifact
        ON direct_edges(caller_artifact_instance_identity);
        """
    )
    return connection


def _insert_edge(
    connection: sqlite3.Connection,
    caller: str,
    kind: str,
    *,
    owner: str = "target/T",
    name: str = "target",
    descriptor: str = "()V",
    opcode: int = 182,
    offset: int = 0,
    payload: object | str | None = None,
) -> None:
    encoded = (
        payload
        if isinstance(payload, str)
        else json.dumps(payload if payload is not None else {})
    )
    connection.execute(
        "INSERT INTO direct_edges VALUES (?, 'artifact-a', ?, ?, ?, ?, ?, ?, ?)",
        (
            caller,
            kind,
            owner,
            name,
            descriptor,
            opcode,
            offset,
            encoded,
        ),
    )


class DirectEdgeLocalityTest(unittest.TestCase):
    def test_sequential_identity_projection_preserves_out_of_order_fallback(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE facts(identity TEXT PRIMARY KEY,value TEXT)"
        )
        connection.executemany(
            "INSERT INTO facts VALUES (?, ?)",
            [("a", "one"), ("b", "two"), ("c", "three"), ("d", "four")],
        )
        projection = oracle._SequentialIdentityProjection(
            connection,
            table="facts",
            identity_column="identity",
            selected_columns=("identity", "value"),
            prefer_table_locality=False,
        )
        try:
            forward = projection.resolve(("b", "d"))
            # ``a`` is now behind the forward cursor and ``missing`` never
            # existed; both take the exact indexed compatibility path.
            fallback = projection.resolve(("a", "missing"))
        finally:
            projection.close()
            connection.close()
        self.assertEqual(
            [(row["identity"], row["value"]) for row in forward],
            [("b", "two"), ("d", "four")],
        )
        self.assertEqual(
            [(row["identity"], row["value"]) for row in fallback],
            [("a", "one")],
        )

    def test_hashed_identity_lookup_reads_dense_payload_rows_by_rowid(self):
        connection = _fact_connection()
        try:
            connection.executemany(
                "INSERT INTO members VALUES (?, 'artifact-a', ?, ?, '()V')",
                [
                    (f"member-{index}", f"caller/C{index}", "run")
                    for index in range(10)
                ],
            )
            expected = {
                str(row["member_identity"]): str(row["class_name"])
                for row in connection.execute(
                    "SELECT member_identity,class_name FROM members "
                    "WHERE member_identity IN (?,?,?)",
                    ("member-3", "member-1", "member-2"),
                )
            }
            traced_sql: list[str] = []
            connection.set_trace_callback(traced_sql.append)
            rows = oracle._identity_rows_with_table_locality(
                connection,
                table="members",
                identity_column="member_identity",
                selected_columns=("member_identity", "class_name"),
                identities=("member-3", "member-1", "member-2"),
            )
            connection.set_trace_callback(None)

            self.assertEqual({
                str(row["member_identity"]): str(row["class_name"])
                for row in rows
            }, expected)
            self.assertTrue(any(
                "SELECT rowid,member_identity" in statement
                for statement in traced_sql
            ))
            self.assertTrue(any(
                "WHERE rowid BETWEEN" in statement
                for statement in traced_sql
            ))
        finally:
            connection.close()

    def test_identity_locality_helper_preserves_without_rowid_fallback(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(
                "CREATE TABLE facts(identity TEXT PRIMARY KEY,value TEXT) "
                "WITHOUT ROWID"
            )
            connection.executemany(
                "INSERT INTO facts VALUES (?, ?)",
                [("a", "one"), ("b", "two")],
            )
            rows = oracle._identity_rows_with_table_locality(
                connection,
                table="facts",
                identity_column="identity",
                selected_columns=("identity", "value"),
                identities=("b", "missing"),
            )
            self.assertEqual(
                [(row["identity"], row["value"]) for row in rows],
                [("b", "two")],
            )
        finally:
            connection.close()

    def test_identity_locality_is_enabled_only_for_paging_risk(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "facts.sqlite"
            connection = sqlite3.connect(database)
            try:
                with patch.object(
                    oracle.Path,
                    "stat",
                    return_value=SimpleNamespace(st_size=11 * 1024**3),
                ), patch.object(
                    oracle,
                    "system_available_memory_bytes",
                    return_value=5 * 1024**3,
                ):
                    self.assertTrue(
                        oracle._prefer_identity_table_locality(connection)
                    )
                with patch.object(
                    oracle.Path,
                    "stat",
                    return_value=SimpleNamespace(st_size=200 * 1024**2),
                ), patch.object(
                    oracle,
                    "system_available_memory_bytes",
                    return_value=512 * 1024**2,
                ):
                    self.assertFalse(
                        oracle._prefer_identity_table_locality(connection)
                    )
                with patch.object(
                    oracle.Path,
                    "stat",
                    return_value=SimpleNamespace(st_size=11 * 1024**3),
                ), patch.object(
                    oracle,
                    "system_available_memory_bytes",
                    return_value=32 * 1024**3,
                ):
                    self.assertFalse(
                        oracle._prefer_identity_table_locality(connection)
                    )
            finally:
                connection.close()

    def test_member_ranges_require_one_contiguous_interval_per_artifact(self):
        connection = _fact_connection()
        try:
            connection.executemany(
                "INSERT INTO members VALUES (?, ?, ?, ?, ?)",
                [
                    ("a-1", "artifact-a", "a/A", "one", "()V"),
                    ("a-2", "artifact-a", "a/A", "two", "()V"),
                    ("b-1", "artifact-b", "b/B", "one", "()V"),
                ],
            )
            self.assertEqual(
                oracle._sequential_member_rowid_ranges(connection),
                {
                    "artifact-a": (1, 2, 2),
                    "artifact-b": (3, 3, 1),
                },
            )

            connection.execute(
                "INSERT INTO members VALUES (?, ?, ?, ?, ?)",
                ("a-3", "artifact-a", "a/A", "three", "()V"),
            )
            self.assertIsNone(
                oracle._sequential_member_rowid_ranges(connection)
            )
        finally:
            connection.close()

    def test_missing_production_column_selects_exact_legacy_fallback(self):
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute(
                "CREATE TABLE members(member_identity TEXT PRIMARY KEY)"
            )
            self.assertIsNone(
                oracle._sequential_member_rowid_ranges(connection)
            )
        finally:
            connection.close()

    def test_local_projection_is_exactly_equal_to_legacy_join(self):
        connection = _fact_connection()
        try:
            connection.executemany(
                "INSERT INTO members VALUES (?, ?, ?, ?, ?)",
                [
                    ("a-main", "artifact-a", "caller/A", "run", "()V"),
                    ("a-field", "artifact-a", "caller/A", "field", "I"),
                    ("b-cross", "artifact-b", "caller/B", "cross", "()V"),
                ],
            )
            _insert_edge(
                connection,
                "a-main",
                "method",
                payload={
                    "interface": False,
                    oracle.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: [
                        "caller/A", "target/T",
                    ],
                },
            )
            _insert_edge(
                connection,
                "a-field",
                "field",
                name="value",
                descriptor="I",
                opcode=180,
                offset=1,
            )
            _insert_edge(
                connection,
                "a-main",
                "invokedynamic_handle_method",
                offset=2,
                payload={"tag": 6, "interface": False},
            )
            _insert_edge(
                connection,
                "a-main",
                "invokedynamic_bootstrap",
                owner="custom/Bootstrap",
                offset=3,
                payload={"bootstrap": {"tag": 6, "interface": False}},
            )
            _insert_edge(
                connection,
                "a-main",
                "type",
                name="",
                descriptor="",
                opcode=187,
                offset=4,
                payload={"type_use_kind": "new"},
            )
            _insert_edge(
                connection,
                "a-main",
                "class_init",
                name="",
                descriptor="",
                opcode=187,
                offset=5,
                payload={"trigger_kind": "new"},
            )
            # The production contract aligns caller and edge artifact
            # identities, but an independently authored store may not. The
            # fast path must preserve the legacy JOIN result in that case.
            _insert_edge(
                connection,
                "b-cross",
                "method",
                offset=6,
                payload={"interface": True},
            )
            # A dangling member is omitted by the legacy INNER JOIN and must
            # remain omitted by the local projection.
            _insert_edge(
                connection,
                "missing",
                "method",
                offset=7,
                payload={"interface": False},
            )
            _insert_edge(
                connection,
                "a-main",
                "invokedynamic_handle_method",
                offset=8,
                payload="not-json",
            )
            connection.commit()

            legacy_issues: list[dict[str, object]] = []
            legacy = oracle._production_direct_truth_for_artifact(
                connection,
                "artifact-a",
                legacy_issues,
                include_structural=True,
            )
            ranges = oracle._sequential_member_rowid_ranges(connection)
            self.assertIsNotNone(ranges)
            traced_sql: list[str] = []
            connection.set_trace_callback(traced_sql.append)
            local_issues: list[dict[str, object]] = []
            local = oracle._production_direct_truth_for_artifact(
                connection,
                "artifact-a",
                local_issues,
                include_structural=True,
                member_rowid_range=ranges["artifact-a"],
            )
            connection.set_trace_callback(None)

            self.assertEqual(local, legacy)
            self.assertEqual(local_issues, legacy_issues)
            self.assertEqual(len(local[0]), 3)
            self.assertEqual(len(local[1]), 2)
            self.assertEqual(len(local[3]), 1)
            direct_queries = [
                statement
                for statement in traced_sql
                if "FROM direct_edges AS e" in statement
            ]
            self.assertEqual(len(direct_queries), 1)
            self.assertNotIn("JOIN members", direct_queries[0])
        finally:
            connection.close()

    def test_projection_count_mismatch_reverts_to_legacy_join(self):
        connection = _fact_connection()
        try:
            connection.execute(
                "INSERT INTO members VALUES (?, ?, ?, ?, ?)",
                ("a-main", "artifact-a", "caller/A", "run", "()V"),
            )
            _insert_edge(
                connection,
                "a-main",
                "method",
                payload={"interface": False},
            )
            expected_issues: list[dict[str, object]] = []
            expected = oracle._production_direct_truth_for_artifact(
                connection, "artifact-a", expected_issues
            )
            traced_sql: list[str] = []
            connection.set_trace_callback(traced_sql.append)
            actual_issues: list[dict[str, object]] = []
            actual = oracle._production_direct_truth_for_artifact(
                connection,
                "artifact-a",
                actual_issues,
                member_rowid_range=(1, 1, 2),
            )
            connection.set_trace_callback(None)
            self.assertEqual(actual, expected)
            self.assertEqual(actual_issues, expected_issues)
            self.assertTrue(any(
                "JOIN members AS m" in statement for statement in traced_sql
            ))
        finally:
            connection.close()

    def test_validated_edge_replay_matches_legacy_join_exactly(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "facts.sqlite"
            connection = _fact_connection(database)
            try:
                connection.execute(
                    "CREATE TABLE artifact_instances ("
                    "artifact_instance_identity TEXT PRIMARY KEY,"
                    "runtime_classpath_index INTEGER NOT NULL)"
                )
                connection.executemany(
                    "INSERT INTO artifact_instances VALUES (?, ?)",
                    [("artifact-a", 0), ("artifact-b", 1)],
                )
                connection.executemany(
                    "INSERT INTO members VALUES (?, ?, ?, ?, ?)",
                    [
                        ("a-main", "artifact-a", "caller/A", "run", "()V"),
                        ("b-main", "artifact-b", "caller/B", "run", "()V"),
                    ],
                )
                _insert_edge(
                    connection,
                    "a-main",
                    "method",
                    payload={"interface": False},
                )
                _insert_edge(
                    connection,
                    "b-main",
                    "field",
                    name="value",
                    descriptor="I",
                    opcode=180,
                    offset=1,
                )
                _insert_edge(
                    connection,
                    "missing",
                    "method",
                    offset=2,
                    payload={"interface": False},
                )
                connection.commit()
            finally:
                connection.close()

            with patch.object(
                oracle, "_sequential_member_rowid_ranges",
            ) as redundant_scan:
                local = list(oracle._iter_validated_direct_edges(
                    database,
                    member_rowid_ranges={
                        "artifact-a": (1, 1, 1),
                        "artifact-b": (2, 2, 1),
                    },
                ))
            redundant_scan.assert_not_called()
            with patch.object(
                oracle, "_sequential_member_rowid_ranges", return_value=None,
            ):
                legacy = list(oracle._iter_validated_direct_edges(database))

            self.assertEqual(local, legacy)
            self.assertEqual(len(local), 2)


class SequentialHashTest(unittest.TestCase):
    def test_jsonl_cursor_matches_per_line_json_decoding(self):
        for payload in (
            "", "{}", "{}\n", "{}\n{\"value\":1}",
            "  {}  \r\n{\"value\":1}\n",
        ):
            self.assertEqual(
                list(oracle._iter_jsonl_values(payload)),
                [json.loads(line) for line in payload.splitlines()],
            )
        for payload in ("not-json", "{} {}\n"):
            with self.assertRaises(json.JSONDecodeError):
                list(oracle._iter_jsonl_values(payload))

    def test_sequential_hash_reads_every_byte_and_reports_bounded_progress(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large.bin"
            payload = bytes(range(256)) * (32 * 1024 + 1)
            path.write_bytes(payload)
            observed: list[tuple[object, ...]] = []

            actual = oracle._sha256_file(
                path,
                progress_callback=lambda *values: observed.append(values),
                progress_phase="integrity",
                progress_message="hashing",
                progress_item="large.bin",
            )

            self.assertEqual(actual, hashlib.sha256(payload).hexdigest())
            self.assertEqual(observed[0], (
                "integrity", "hashing", 0, len(payload), "large.bin",
            ))
            self.assertEqual(observed[-1], (
                "integrity", "hashing", len(payload), len(payload),
                "large.bin",
            ))
            self.assertLessEqual(len(observed), 22)


class ReconciliationLocalityTest(unittest.TestCase):
    def test_fact_store_chunk_order_streams_every_record_in_write_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "facts.sqlite"
            with BinaryFactStore(database) as store:
                expected = [f"edge-{index:05d}" for index in range(4_501)]
                store.add_reconciliation_payloads(
                    analysis_context_identity="context",
                    record_kind="member_resolution",
                    records=(
                        (
                            "resolved",
                            hashlib.sha256(edge.encode("utf-8")).hexdigest(),
                            {
                                "direct_edge_identity": edge,
                                "member_resolution_status": "resolved",
                            },
                        )
                        for edge in expected
                    ),
                    collect_identities=False,
                )
                order_rows = list(store.connection.execute(
                    "SELECT record_kind,chunk_ordinal "
                    "FROM reconciliation_chunk_order "
                    "ORDER BY record_kind,chunk_ordinal"
                ))
                actual = [
                    row["direct_edge_identity"]
                    for row in oracle._iter_reconciliation(
                        store.connection, "member_resolution"
                    )
                ]
                hydrated = [
                    row["direct_edge_identity"]
                    for row in store.reconciliation_payloads(
                        "member_resolution"
                    )
                ]
                ordered_content_identity = store.content_identity()

                self.assertEqual(actual, expected)
                self.assertEqual(hydrated, expected)
                self.assertTrue(
                    oracle._has_complete_reconciliation_chunk_order(
                        store.connection, "member_resolution"
                    )
                )
                self.assertEqual(
                    [int(row[1]) for row in order_rows], [0, 1, 2]
                )

                # The order table is a locality hint, never a completeness
                # authority. Removing one hint must move, not omit, its chunk.
                store.connection.execute(
                    "DELETE FROM reconciliation_chunk_order "
                    "WHERE chunk_ordinal=1"
                )
                self.assertFalse(
                    oracle._has_complete_reconciliation_chunk_order(
                        store.connection, "member_resolution"
                    )
                )
                self.assertNotEqual(
                    store.content_identity(), ordered_content_identity
                )
                complete = [
                    row["direct_edge_identity"]
                    for row in oracle._iter_reconciliation(
                        store.connection, "member_resolution"
                    )
                ]
                hydrated_complete = [
                    row["direct_edge_identity"]
                    for row in store.reconciliation_payloads(
                        "member_resolution"
                    )
                ]
                self.assertEqual(len(complete), len(expected))
                self.assertEqual(set(complete), set(expected))
                self.assertEqual(set(hydrated_complete), set(expected))

    def test_chunk_ordinal_is_reused_after_transaction_rollback(self):
        with BinaryFactStore() as store:
            store.connection.execute("BEGIN")
            store.add_reconciliation_payloads(
                analysis_context_identity="context",
                record_kind="member_resolution",
                records=(("resolved", "a" * 64, {
                    "direct_edge_identity": "edge-rolled-back",
                    "member_resolution_status": "resolved",
                }),),
                collect_identities=False,
                manage_transaction=False,
            )
            store.connection.rollback()
            store.add_reconciliation_payloads(
                analysis_context_identity="context",
                record_kind="member_resolution",
                records=(("resolved", "b" * 64, {
                    "direct_edge_identity": "edge-committed",
                    "member_resolution_status": "resolved",
                }),),
                collect_identities=False,
            )
            ordinal = store.connection.execute(
                "SELECT chunk_ordinal FROM reconciliation_chunk_order"
            ).fetchone()[0]
            self.assertEqual(int(ordinal), 0)


if __name__ == "__main__":
    unittest.main()
