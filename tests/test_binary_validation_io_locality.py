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


if __name__ == "__main__":
    unittest.main()
