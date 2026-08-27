#!/usr/bin/env python3
"""ArtifactInstance-keyed SQLite store for ASM binary facts."""

from __future__ import annotations

from contextlib import nullcontext
from functools import lru_cache
import hashlib
from itertools import chain
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable, Iterator, Mapping
import zlib

from binary_artifact_diff import ArtifactSnapshot
from binary_first_contract import (
    BinaryFirstContractError,
    JVM_TEXT_TRANSPORT_PREFIX,
    StreamingCanonicalSequence,
    canonical_identity_native_json,
    canonical_identity_streaming,
    canonical_json_string,
    surrogate_safe_json_dumps,
    transport_jvm_value,
)
from binary_first_model import ArtifactInstance


SCHEMA_VERSION = "binary-fact-sqlite-v9"
RECONCILIATION_KIND_CODES = {
    "provider_binding": 1,
    "class_definition": 2,
    "member_resolution": 3,
    "dispatch_resolution": 4,
    "type_resolution": 5,
    "class_initialization_resolution": 6,
    "linkage_resolution": 7,
    "resource_selection": 8,
}
METHOD_HANDLE_REFERENCE_KIND_BY_TAG = {
    1: "REF_getField",
    2: "REF_getStatic",
    3: "REF_putField",
    4: "REF_putStatic",
    5: "REF_invokeVirtual",
    6: "REF_invokeStatic",
    7: "REF_invokeSpecial",
    8: "REF_newInvokeSpecial",
    9: "REF_invokeInterface",
}
LOADING_CONSTRAINT_TYPE_OWNERS_KEY = "loading_constraint_type_owners"
RECONCILIATION_CODE_KINDS = {
    value: key for key, value in RECONCILIATION_KIND_CODES.items()
}
_RUNTIME_TRIGGER_SUMMARY_FIELDS = frozenset({
    "has_runtime_annotations",
    "hierarchy_types",
    "has_main_method",
})
_RUNTIME_TRIGGER_SUMMARY_SCAN_ATTEMPTS = 3


class BinaryFactStoreError(BinaryFirstContractError):
    pass


def _json(value: Any) -> str:
    return surrogate_safe_json_dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _json_and_transport_jvm_value(value: Any) -> tuple[Any, str]:
    """Serialize ordinary JVM facts once and transport exceptional text.

    The previous path recursively scanned the complete fact tree for JVM text
    requiring transport and then traversed it again to produce JSON.  Let the
    C JSON encoder and UTF-8 encoder detect the overwhelmingly rare surrogate
    case; only that exceptional case pays for the defensive tree conversion
    and second serialization.
    """

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    try:
        encoded.encode("utf-8")
    except UnicodeEncodeError:
        pass
    else:
        # A raw JVM value beginning with the reserved transport prefix must
        # also be escaped to keep restore_jvm_text collision-free.  Searching
        # the serialized tree avoids a second Python-level recursive walk.
        if f'"{JVM_TEXT_TRANSPORT_PREFIX}' not in encoded:
            return value, encoded
    transported = transport_jvm_value(value)
    return transported, _json(transported)


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity_native_json(
        namespace, payload, schema_version="1"
    )


_DIRECT_EDGE_IDENTITY_PREFIX = (
    b'{"namespace":"binary_direct_edge_identity","payload":'
)
_DIRECT_EDGE_IDENTITY_SUFFIX = b',"schema_version":"1"}'


@lru_cache(maxsize=4_096)
def _cached_canonical_edge_json_bytes(value: str) -> bytes:
    return canonical_json_string(value).encode("utf-8")


@lru_cache(maxsize=4_096)
def _cached_canonical_edge_integer_bytes(value: int) -> bytes:
    return str(int(value)).encode("ascii")


def _direct_edge_identity_from_json(
    caller_member_identity: str,
    bytecode_offset: int,
    instruction_index: int,
    edge_kind: str,
    symbolic_owner: str,
    symbolic_name: str,
    symbolic_descriptor: str,
    edge_json: str,
) -> str:
    """Hash one edge while reusing its already-canonical payload JSON.

    The key order and scalar spellings below are the exact output of the
    frozen sorted compact JSON encoder used by ``_identity``.  All values are
    native scalars and ``edge_json`` is produced by ``_json`` (or read from a
    same-schema fact store), so this removes a redundant payload decode/tree
    encode without changing one hashed byte.
    """

    body = b"".join((
        b'{"bytecode_offset":',
        _cached_canonical_edge_integer_bytes(bytecode_offset),
        b',"caller_member_identity":',
        _cached_canonical_edge_json_bytes(caller_member_identity),
        b',"edge_kind":',
        _cached_canonical_edge_json_bytes(edge_kind),
        b',"edge_payload":',
        edge_json.encode("utf-8"),
        b',"instruction_index":',
        _cached_canonical_edge_integer_bytes(instruction_index),
        b',"symbolic_descriptor":',
        _cached_canonical_edge_json_bytes(symbolic_descriptor),
        b',"symbolic_name":',
        _cached_canonical_edge_json_bytes(symbolic_name),
        b',"symbolic_owner":',
        _cached_canonical_edge_json_bytes(symbolic_owner),
        b"}",
    ))
    digest = hashlib.sha256(_DIRECT_EDGE_IDENTITY_PREFIX)
    digest.update(body)
    digest.update(_DIRECT_EDGE_IDENTITY_SUFFIX)
    return digest.hexdigest()


class BinaryFactStore:
    FACT_INSERT_CHUNK_SIZE = 8_000

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        defer_secondary_indexes: bool = False,
        bulk_load_transaction: bool = False,
    ):
        self.path = str(path)
        self.connection = sqlite3.connect(self.path)
        self._runtime_trigger_summary_cache: dict[str, Any] | None = None
        self._runtime_trigger_summary_data_version: int | None = None
        self._bulk_load_transaction = False
        try:
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA journal_mode=MEMORY")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self._create_schema()
            if not defer_secondary_indexes:
                self.ensure_secondary_indexes()
            if self.connection.execute(
                "SELECT 1 FROM classes LIMIT 1"
            ).fetchone() is None:
                # An empty store has an exact empty summary.  Keeping that
                # summary current while snapshots are ingested avoids a later
                # full decompression pass over every stored class fact.
                self._runtime_trigger_summary_cache = (
                    self._empty_runtime_trigger_summary()
                )
                self._runtime_trigger_summary_data_version = (
                    self._runtime_trigger_data_version()
                )
            self._bulk_load_transaction = bool(bulk_load_transaction)
            if self._bulk_load_transaction:
                self.connection.execute("BEGIN")
        except BaseException:
            # ``sqlite3.Connection`` owns an OS handle as soon as connect()
            # succeeds.  Schema/index/transaction setup can still fail (disk
            # full, corruption, interruption, injected SQLite error); never
            # leave that partially constructed handle to cyclic GC.
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def _create_schema(self):
        existing_tables = {
            str(row[0]) for row in self.connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if existing_tables:
            existing_version = None
            if "metadata" in existing_tables:
                try:
                    row = self.connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()
                    existing_version = str(row[0]) if row else None
                except sqlite3.DatabaseError:
                    existing_version = None
            if existing_version != SCHEMA_VERSION:
                raise BinaryFactStoreError(
                    "FACT_STORE_SCHEMA_VERSION_MISMATCH",
                    f"expected={SCHEMA_VERSION}; actual={existing_version or 'missing'}",
                )
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_instances (
                artifact_instance_identity TEXT PRIMARY KEY,
                coord TEXT NOT NULL,
                outer_artifact_sha256 TEXT NOT NULL,
                container_entry TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                runtime_profile_identity TEXT NOT NULL,
                loader_realm_identity TEXT NOT NULL,
                runtime_path_kind TEXT NOT NULL,
                runtime_classpath_index INTEGER NOT NULL,
                container_loader_policy_version TEXT NOT NULL,
                runtime_code_source_origin_identity TEXT NOT NULL,
                inventory_digest TEXT NOT NULL,
                parser_identity TEXT NOT NULL,
                coverage_status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS archive_entries (
                physical_entry_identity TEXT PRIMARY KEY,
                artifact_instance_identity TEXT NOT NULL REFERENCES artifact_instances(artifact_instance_identity),
                name TEXT NOT NULL,
                name_ordinal INTEGER NOT NULL,
                archive_ordinal INTEGER NOT NULL,
                kind TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                byte_length INTEGER NOT NULL,
                logical_class_entry TEXT NOT NULL,
                logical_resource_entry TEXT NOT NULL,
                multi_release_version INTEGER NOT NULL,
                resource_category TEXT NOT NULL,
                normalized_resource_digest TEXT NOT NULL,
                resource_semantic_json TEXT NOT NULL,
                entry_json TEXT NOT NULL,
                UNIQUE(artifact_instance_identity, name, name_ordinal)
            );
            CREATE TABLE IF NOT EXISTS classes (
                class_variant_identity TEXT PRIMARY KEY,
                artifact_instance_identity TEXT NOT NULL REFERENCES artifact_instances(artifact_instance_identity),
                physical_entry_identity TEXT NOT NULL REFERENCES archive_entries(physical_entry_identity),
                physical_entry_label TEXT NOT NULL,
                class_name TEXT NOT NULL,
                class_major INTEGER,
                multi_release_version INTEGER NOT NULL,
                class_bytes_sha256 TEXT NOT NULL,
                class_contract_digest TEXT NOT NULL,
                parse_status TEXT NOT NULL,
                failure_kind TEXT NOT NULL,
                class_access INTEGER,
                super_name TEXT,
                interfaces_json TEXT NOT NULL,
                nest_host TEXT,
                nest_members_json TEXT NOT NULL,
                has_runtime_annotations INTEGER NOT NULL,
                class_bytes_zlib BLOB NOT NULL,
                fact_zlib BLOB NOT NULL,
                UNIQUE(artifact_instance_identity, physical_entry_label)
            );
            CREATE TABLE IF NOT EXISTS members (
                member_identity TEXT PRIMARY KEY,
                class_variant_identity TEXT NOT NULL REFERENCES classes(class_variant_identity),
                artifact_instance_identity TEXT NOT NULL REFERENCES artifact_instances(artifact_instance_identity),
                class_name TEXT NOT NULL,
                member_kind TEXT NOT NULL,
                member_name TEXT NOT NULL,
                descriptor TEXT NOT NULL,
                access_flags INTEGER NOT NULL,
                contract_json TEXT NOT NULL,
                implementation_digest TEXT NOT NULL,
                UNIQUE(class_variant_identity, member_kind, member_name, descriptor)
            );
            CREATE TABLE IF NOT EXISTS direct_edges (
                direct_edge_identity TEXT PRIMARY KEY,
                caller_member_identity TEXT NOT NULL REFERENCES members(member_identity),
                caller_artifact_instance_identity TEXT NOT NULL REFERENCES artifact_instances(artifact_instance_identity),
                caller_class_variant_identity TEXT NOT NULL REFERENCES classes(class_variant_identity),
                instruction_index INTEGER NOT NULL,
                bytecode_offset INTEGER NOT NULL,
                edge_kind TEXT NOT NULL,
                opcode INTEGER,
                symbolic_owner TEXT NOT NULL,
                symbolic_name TEXT NOT NULL,
                symbolic_descriptor TEXT NOT NULL,
                edge_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS resources (
                physical_entry_identity TEXT PRIMARY KEY REFERENCES archive_entries(physical_entry_identity),
                artifact_instance_identity TEXT NOT NULL REFERENCES artifact_instances(artifact_instance_identity),
                resource_name TEXT NOT NULL,
                resource_category TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                normalized_resource_digest TEXT NOT NULL
                ,resource_semantic_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reconciliation_records (
                chunk_identity BLOB PRIMARY KEY,
                record_kind INTEGER NOT NULL,
                record_count INTEGER NOT NULL,
                payload_zlib BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS reconciliation_chunk_order (
                record_kind INTEGER NOT NULL,
                chunk_ordinal INTEGER NOT NULL,
                chunk_identity BLOB NOT NULL UNIQUE
                    REFERENCES reconciliation_records(chunk_identity),
                PRIMARY KEY(record_kind, chunk_ordinal)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS source_overlays (
                overlay_identity TEXT PRIMARY KEY,
                analysis_context_identity TEXT NOT NULL,
                binary_member_identity TEXT NOT NULL REFERENCES members(member_identity),
                mapping_status TEXT NOT NULL,
                source_location_json TEXT NOT NULL,
                conflict_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS inline_overlays (
                inline_overlay_identity TEXT PRIMARY KEY,
                analysis_context_identity TEXT NOT NULL,
                changed_field_member_identity TEXT NOT NULL REFERENCES members(member_identity),
                consumer_member_identity TEXT REFERENCES members(member_identity),
                consumption_state TEXT NOT NULL,
                binding_certainty TEXT NOT NULL,
                coverage_status TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            """
        )
        self.connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        self.connection.commit()

    def ensure_secondary_indexes(self) -> None:
        """Create lookup indexes after an optional append-only bulk load."""

        if self._bulk_load_transaction:
            self.connection.commit()
            self._bulk_load_transaction = False
        self.connection.executescript(
            """
            CREATE INDEX IF NOT EXISTS artifact_instances_coord
                ON artifact_instances(coord);
            CREATE INDEX IF NOT EXISTS artifact_instances_runtime_slot
                ON artifact_instances(
                    runtime_profile_identity,
                    loader_realm_identity,
                    runtime_classpath_index
                );
            CREATE INDEX IF NOT EXISTS archive_entries_class
                ON archive_entries(
                    artifact_instance_identity,
                    logical_class_entry,
                    multi_release_version
                );
            CREATE INDEX IF NOT EXISTS classes_runtime_lookup
                ON classes(
                    artifact_instance_identity,
                    class_name,
                    multi_release_version
                );
            CREATE INDEX IF NOT EXISTS members_symbolic_lookup
                ON members(class_name, member_kind, member_name, descriptor);
            CREATE INDEX IF NOT EXISTS direct_edges_symbolic_target
                ON direct_edges(
                    symbolic_owner,
                    symbolic_name,
                    symbolic_descriptor
                );
            CREATE INDEX IF NOT EXISTS direct_edges_caller_artifact
                ON direct_edges(caller_artifact_instance_identity);
            CREATE INDEX IF NOT EXISTS direct_edges_caller_member
                ON direct_edges(caller_member_identity);
            CREATE INDEX IF NOT EXISTS reconciliation_records_kind
                ON reconciliation_records(record_kind);
            """
        )

    def add_artifact_snapshot(
        self,
        instance: ArtifactInstance,
        snapshot: ArtifactSnapshot,
    ) -> dict[str, int]:
        if snapshot.artifact_instance_identity != instance.identity:
            raise BinaryFactStoreError(
                "FACT_STORE_ARTIFACT_IDENTITY_MISMATCH",
                "snapshot and ArtifactInstance identities differ",
            )
        if snapshot.artifact_content_sha256 != instance.content_sha256:
            raise BinaryFactStoreError(
                "FACT_STORE_ARTIFACT_CONTENT_MISMATCH",
                "snapshot bytes are not the ArtifactInstance content",
            )
        current_data_version = self._runtime_trigger_data_version()
        if (
            self._runtime_trigger_summary_cache is not None
            and self._runtime_trigger_summary_data_version
            != current_data_version
        ):
            # Another connection committed since this cache was captured.
            # Its rows are visible to subsequent reads but cannot be merged
            # safely with a summary that predates them.
            self._runtime_trigger_summary_cache = None
            self._runtime_trigger_summary_data_version = None
        prior_runtime_summary = self._runtime_trigger_summary_cache
        prior_runtime_summary_data_version = (
            self._runtime_trigger_summary_data_version
        )
        added_has_runtime_annotations = False
        added_hierarchy_types: set[str] = set()
        added_has_main_method = False
        merged_runtime_summary: dict[str, Any] | None = None
        entry_by_label = {
            f"{item.name}#occurrence={item.name_ordinal}": item
            for item in snapshot.entries
        }
        payload_by_label = dict(snapshot.class_payloads)
        counts = {"entries": 0, "classes": 0, "members": 0, "edges": 0, "resources": 0}
        try:
            transaction = (
                nullcontext()
                if self._bulk_load_transaction
                else self.connection
            )
            with transaction:
                self.connection.execute(
                    """
                    INSERT INTO artifact_instances VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        instance.identity,
                        instance.coord,
                        instance.outer_artifact_sha256,
                        instance.container_entry,
                        instance.content_sha256,
                        instance.runtime_profile_identity,
                        instance.path_owner_loader_realm_identity,
                        instance.runtime_path_kind,
                        instance.runtime_classpath_index,
                        instance.container_loader_policy_version,
                        instance.runtime_code_source_origin_identity,
                        snapshot.inventory_digest,
                        snapshot.parser_identity,
                        snapshot.class_fact_coverage_status,
                    ),
                )
                self.connection.executemany(
                    "INSERT INTO archive_entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        (
                            entry.physical_entry_identity,
                            instance.identity,
                            entry.name,
                            entry.name_ordinal,
                            entry.archive_ordinal,
                            entry.kind,
                            entry.content_sha256,
                            entry.byte_length,
                            entry.logical_class_entry,
                            entry.logical_resource_entry,
                            entry.multi_release_version,
                            entry.resource_category,
                            entry.normalized_resource_digest,
                            _json(entry.resource_semantic_facts),
                            _json(vars(entry)),
                        )
                        for entry in snapshot.entries
                    ),
                )
                counts["entries"] = len(snapshot.entries)
                resource_entries = tuple(
                    entry for entry in snapshot.entries
                    if entry.kind == "resource" and entry.runtime_effective
                )
                self.connection.executemany(
                    "INSERT INTO resources VALUES(?,?,?,?,?,?,?)",
                    (
                        (
                            entry.physical_entry_identity,
                            instance.identity,
                            entry.logical_resource_entry or entry.name,
                            entry.resource_category,
                            entry.content_sha256,
                            entry.normalized_resource_digest,
                            _json(entry.resource_semantic_facts),
                        )
                        for entry in resource_entries
                    )
                )
                counts["resources"] = len(resource_entries)

                class_rows = []
                member_rows = []
                edge_rows = []

                def flush_fact_rows() -> None:
                    if class_rows:
                        self.connection.executemany(
                            "INSERT INTO classes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            class_rows,
                        )
                    if member_rows:
                        self.connection.executemany(
                            "INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?)",
                            member_rows,
                        )
                    if edge_rows:
                        self.connection.executemany(
                            "INSERT INTO direct_edges VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                            edge_rows,
                        )
                    class_rows.clear()
                    member_rows.clear()
                    edge_rows.clear()

                def flush_fact_rows_if_full() -> None:
                    # A single obfuscated/generated class can contain far more
                    # members and edges than a whole ordinary archive.  Bound
                    # every temporary row buffer independently instead of
                    # waiting for the number of classes to reach the limit.
                    if max(len(class_rows), len(member_rows), len(edge_rows)) >= (
                        self.FACT_INSERT_CHUNK_SIZE
                    ):
                        flush_fact_rows()

                for source_record in snapshot.class_records:
                    source_label = str(source_record.get("class_entry") or "")
                    entry = entry_by_label.get(source_label)
                    if entry is None:
                        raise BinaryFactStoreError(
                            "FACT_STORE_CLASS_ENTRY_UNBOUND", source_label
                        )
                    class_payload = payload_by_label.get(source_label)
                    if class_payload is None:
                        raise BinaryFactStoreError(
                            "FACT_STORE_CLASS_PAYLOAD_UNBOUND", source_label
                        )
                    # JVM constant-pool text is UTF-16 and can legally contain
                    # an unpaired surrogate, while Python's SQLite adapter
                    # requires strict UTF-8 text.  Preserve those rare values
                    # with the reversible internal transport used by the
                    # independent oracle; ordinary strings remain untouched.
                    record, record_fact_json = _json_and_transport_jvm_value(
                        source_record
                    )
                    # The lookup above proves this required binding is present;
                    # retain its transported representation without inventing a
                    # second empty-label state.
                    label = str(record["class_entry"])
                    parse_status = (
                        "parsed" if record.get("frame_type") == "class_fact" else "failed"
                    )
                    (
                        record_has_runtime_annotations,
                        record_hierarchy_types,
                        record_has_main_method,
                    ) = self._runtime_trigger_fact_components(
                        record,
                        include_main_method=parse_status == "parsed",
                    )
                    added_hierarchy_types.update(record_hierarchy_types)
                    added_has_runtime_annotations = (
                        added_has_runtime_annotations
                        or record_has_runtime_annotations
                    )
                    added_has_main_method = (
                        added_has_main_method or record_has_main_method
                    )
                    class_name = str(record.get("class_name") or entry.logical_class_entry.removesuffix(".class"))
                    variant_identity = _identity(
                        "class_variant_identity",
                        {
                            "artifact_instance_identity": instance.identity,
                            "physical_entry_identity": entry.physical_entry_identity,
                            "class_name": class_name,
                            "multi_release_version": entry.multi_release_version,
                            "class_bytes_sha256": record.get("class_bytes_sha256"),
                        },
                    )
                    class_rows.append(
                        (
                            variant_identity,
                            instance.identity,
                            entry.physical_entry_identity,
                            label,
                            class_name,
                            record.get("class_major"),
                            entry.multi_release_version,
                            str(record.get("class_bytes_sha256") or ""),
                            str(record.get("class_contract_digest") or ""),
                            parse_status,
                            str(record.get("failure_kind") or ""),
                            record.get("class_access"),
                            record.get("super_name"),
                            _json(record.get("interfaces") or []),
                            record.get("nest_host"),
                            _json(record.get("nest_members") or []),
                            int(record_has_runtime_annotations),
                            sqlite3.Binary(zlib.compress(class_payload, level=1)),
                            sqlite3.Binary(zlib.compress(
                                record_fact_json.encode("utf-8"), level=1
                            )),
                        )
                    )
                    counts["classes"] += 1
                    flush_fact_rows_if_full()
                    if parse_status != "parsed":
                        continue
                    for field in record.get("fields") or ():
                        _member_identity, member_row = self._member_values(
                            variant_identity,
                            instance.identity,
                            class_name,
                            "field",
                            field,
                            "",
                        )
                        member_rows.append(member_row)
                        counts["members"] += 1
                        flush_fact_rows_if_full()
                    for method in record.get("methods") or ():
                        contract = method.get("contract") or {}
                        member_identity, member_row = self._member_values(
                            variant_identity,
                            instance.identity,
                            class_name,
                            "method",
                            contract,
                            str(method.get("implementation_digest") or ""),
                        )
                        member_rows.append(member_row)
                        counts["members"] += 1
                        flush_fact_rows_if_full()
                        for instruction_index, instruction in enumerate(method.get("instructions") or ()):
                            for edge in self._instruction_edges(instruction):
                                edge_json = _json(edge["payload"])
                                edge_identity = _direct_edge_identity_from_json(
                                    member_identity,
                                    edge["bytecode_offset"],
                                    instruction_index,
                                    edge["edge_kind"],
                                    edge["symbolic_owner"],
                                    edge["symbolic_name"],
                                    edge["symbolic_descriptor"],
                                    edge_json,
                                )
                                edge_rows.append(
                                    (
                                        edge_identity,
                                        member_identity,
                                        instance.identity,
                                        variant_identity,
                                        instruction_index,
                                        edge["bytecode_offset"],
                                        edge["edge_kind"],
                                        edge["opcode"],
                                        edge["symbolic_owner"],
                                        edge["symbolic_name"],
                                        edge["symbolic_descriptor"],
                                        edge_json,
                                    )
                                )
                                counts["edges"] += 1
                                flush_fact_rows_if_full()
                flush_fact_rows()
                if prior_runtime_summary is not None:
                    merged_runtime_summary = {
                        "has_runtime_annotations": bool(
                            prior_runtime_summary["has_runtime_annotations"]
                            or added_has_runtime_annotations
                        ),
                        "hierarchy_types": frozenset(
                            set(prior_runtime_summary["hierarchy_types"])
                            | added_hierarchy_types
                        ),
                        "has_main_method": bool(
                            prior_runtime_summary["has_main_method"]
                            or added_has_main_method
                        ),
                    }
        except sqlite3.IntegrityError as error:
            if self._bulk_load_transaction:
                self.connection.rollback()
                self._bulk_load_transaction = False
                # The rollback also removes snapshots successfully added by
                # earlier calls in this bulk transaction, so their incremental
                # summary must not survive it.  A lazy database scan remains
                # exact for whatever state is now present.
                self._runtime_trigger_summary_cache = None
                self._runtime_trigger_summary_data_version = None
            raise BinaryFactStoreError(
                "FACT_STORE_IDENTITY_CONFLICT", str(error)
            ) from error
        except BaseException:
            if self._bulk_load_transaction:
                # nullcontext deliberately leaves the caller-owned bulk
                # transaction open for non-integrity failures.  Its visible
                # rows may be partial, so force the exact database fallback.
                self._runtime_trigger_summary_cache = None
                self._runtime_trigger_summary_data_version = None
            raise
        if merged_runtime_summary is not None:
            current_data_version = self._runtime_trigger_data_version()
            if current_data_version == prior_runtime_summary_data_version:
                self._runtime_trigger_summary_cache = merged_runtime_summary
                self._runtime_trigger_summary_data_version = (
                    current_data_version
                )
            else:
                # A concurrent connection committed between the initial cache
                # check and this transaction.  A lazy scan is the only exact
                # merge because that writer's facts were not in either input.
                self._runtime_trigger_summary_cache = None
                self._runtime_trigger_summary_data_version = None
        return counts

    def _insert_member(
        self,
        class_variant_identity: str,
        artifact_instance_identity: str,
        class_name: str,
        member_kind: str,
        contract: dict[str, Any],
        implementation_digest: str,
    ) -> str:
        member_identity, values = self._member_values(
            class_variant_identity,
            artifact_instance_identity,
            class_name,
            member_kind,
            contract,
            implementation_digest,
        )
        self.connection.execute(
            "INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?)", values
        )
        return member_identity

    @staticmethod
    def _member_values(
        class_variant_identity: str,
        artifact_instance_identity: str,
        class_name: str,
        member_kind: str,
        contract: dict[str, Any],
        implementation_digest: str,
    ) -> tuple[str, tuple[Any, ...]]:
        member_name = str(contract.get("name") or "")
        descriptor = str(contract.get("descriptor") or "")
        member_identity = _identity(
            "binary_member_identity",
            {
                "class_variant_identity": class_variant_identity,
                "member_kind": member_kind,
                "owner": class_name,
                "name": member_name,
                "descriptor": descriptor,
            },
        )
        values = (
            member_identity,
            class_variant_identity,
            artifact_instance_identity,
            class_name,
            member_kind,
            member_name,
            descriptor,
            int(contract.get("access") or 0),
            _json(contract),
            implementation_digest,
        )
        return member_identity, values

    @staticmethod
    def _instruction_edges(instruction: Any) -> list[dict[str, Any]]:
        if not isinstance(instruction, list) or len(instruction) < 2:
            return []
        kind = instruction[0]
        try:
            bci = int(instruction[1])
        except (TypeError, ValueError):
            return []
        if kind == "method" and len(instruction) >= 7:
            edge = {
                "bytecode_offset": bci,
                "edge_kind": "method",
                "opcode": int(instruction[2]),
                "symbolic_owner": str(instruction[3]),
                "symbolic_name": str(instruction[4]),
                "symbolic_descriptor": str(instruction[5]),
                "payload": {"interface": bool(instruction[6])},
            }
            edge = BinaryFactStore._with_loading_constraint_type_owners(
                edge, member_kind="method"
            )
            result = [edge]
            if edge["opcode"] == 184:
                result.append({
                    **edge,
                    "edge_kind": "class_init",
                    "symbolic_name": "<clinit>",
                    "symbolic_descriptor": "()V",
                    "payload": {
                        "trigger_kind": "invokestatic",
                        "trigger_member_name": instruction[4],
                        "trigger_member_descriptor": instruction[5],
                    },
                })
            return result
        if kind == "field" and len(instruction) >= 6:
            edge = {
                "bytecode_offset": bci,
                "edge_kind": "field",
                "opcode": int(instruction[2]),
                "symbolic_owner": str(instruction[3]),
                "symbolic_name": str(instruction[4]),
                "symbolic_descriptor": str(instruction[5]),
                "payload": {},
            }
            edge = BinaryFactStore._with_loading_constraint_type_owners(
                edge, member_kind="field"
            )
            result = [edge]
            if edge["opcode"] in {178, 179}:
                result.append({
                    **edge,
                    "edge_kind": "class_init",
                    "symbolic_name": "<clinit>",
                    "symbolic_descriptor": "()V",
                    "payload": {
                        "trigger_kind": "getstatic" if edge["opcode"] == 178 else "putstatic",
                        "trigger_member_name": instruction[4],
                        "trigger_member_descriptor": instruction[5],
                    },
                })
            return result
        if kind == "type" and len(instruction) >= 4:
            edge = {
                "bytecode_offset": bci,
                "edge_kind": "type",
                "opcode": int(instruction[2]),
                "symbolic_owner": str(instruction[3]),
                "symbolic_name": "<type>",
                "symbolic_descriptor": str(instruction[3]),
                "payload": {"type_use_kind": {
                    187: "new", 189: "anewarray", 192: "checkcast",
                    193: "instanceof", 197: "multianewarray",
                }.get(int(instruction[2]), "type_instruction")},
            }
            result = [edge]
            if edge["opcode"] == 187:
                result.append({
                    **edge,
                    "edge_kind": "class_init",
                    "symbolic_name": "<clinit>",
                    "symbolic_descriptor": "()V",
                    "payload": {"trigger_kind": "new"},
                })
            return result
        if kind == "multianewarray" and len(instruction) >= 4:
            descriptor = str(instruction[2])
            return [{
                "bytecode_offset": bci,
                "edge_kind": "type",
                "opcode": 197,
                "symbolic_owner": BinaryFactStore._type_symbolic_owner(descriptor),
                "symbolic_name": "<type>",
                "symbolic_descriptor": descriptor,
                "payload": {
                    "type_use_kind": "multianewarray",
                    "dimensions": int(instruction[3]),
                },
            }]
        if kind == "invokedynamic" and len(instruction) >= 6:
            bootstrap = instruction[4] if isinstance(instruction[4], dict) else {}
            result = [{
                "bytecode_offset": bci,
                "edge_kind": "invokedynamic_bootstrap",
                "opcode": 186,
                "symbolic_owner": str(bootstrap.get("owner") or ""),
                "symbolic_name": str(bootstrap.get("name") or ""),
                "symbolic_descriptor": str(bootstrap.get("descriptor") or ""),
                "payload": {
                    "callsite_name": instruction[2],
                    "callsite_descriptor": instruction[3],
                    "bootstrap": bootstrap,
                    "arguments": instruction[5],
                },
            }]
            if bootstrap.get("kind") == "handle":
                result[0] = (
                    BinaryFactStore._method_handle_with_loading_constraint_types(
                        result[0], bootstrap
                    )
                )
            handles = []
            BinaryFactStore._collect_handles(instruction[5], handles)
            for index, handle in enumerate(handles):
                handle_edge = {
                    "bytecode_offset": bci,
                    "edge_kind": f"invokedynamic_handle_{index}",
                    "opcode": 186,
                    "symbolic_owner": str(handle.get("owner") or ""),
                    "symbolic_name": str(handle.get("name") or ""),
                    "symbolic_descriptor": str(handle.get("descriptor") or ""),
                    "payload": handle,
                }
                result.append(
                    BinaryFactStore._method_handle_with_loading_constraint_types(
                        handle_edge, handle
                    )
                )
            result.extend(BinaryFactStore._method_descriptor_type_edges(
                str(instruction[3]), bci,
                type_use_kind="invokedynamic_callsite_descriptor",
                opcode=186,
            ))
            bootstrap_handle = (
                bootstrap if bootstrap.get("kind") == "handle" else None
            )
            for handle in (
                *((bootstrap_handle,) if bootstrap_handle else ()),
                *handles,
            ):
                result.extend(BinaryFactStore._method_handle_type_edges(
                    handle, bci, opcode=186
                ))
            result.extend(BinaryFactStore._bootstrap_argument_type_edges(
                instruction[5], bci, opcode=186
            ))
            return BinaryFactStore._deduplicate_type_edges(result)
        if kind == "ldc" and len(instruction) >= 3 and isinstance(instruction[2], dict):
            constant = instruction[2]
            if constant.get("kind") == "method_type":
                return BinaryFactStore._method_type_edges(constant, bci)
            if constant.get("kind") in {"type", "handle", "constant_dynamic"}:
                constant_kind = str(constant.get("kind"))
                descriptor = str(constant.get("descriptor") or "")
                owner = str(constant.get("owner") or "")
                if constant_kind == "type":
                    owner = BinaryFactStore._type_symbolic_owner(descriptor)
                result = [{
                    "bytecode_offset": bci,
                    "edge_kind": "type" if constant_kind == "type" else f"ldc_{constant_kind}",
                    "opcode": 18,
                    "symbolic_owner": owner,
                    "symbolic_name": "<type>" if constant_kind == "type" else str(constant.get("name") or "<constant>"),
                    "symbolic_descriptor": descriptor,
                    "payload": {
                        **constant,
                        "type_use_kind": "class_literal" if constant_kind == "type" else constant_kind,
                    },
                }]
                if constant_kind == "handle":
                    result[0] = (
                        BinaryFactStore._method_handle_with_loading_constraint_types(
                            result[0], constant
                        )
                    )
                handles = []
                if constant_kind == "constant_dynamic":
                    bootstrap = constant.get("bootstrap")
                    if isinstance(bootstrap, dict) and bootstrap.get("kind") == "handle":
                        bootstrap_edge = {
                            "bytecode_offset": bci,
                            "edge_kind": "ldc_constant_dynamic_bootstrap",
                            "opcode": 18,
                            "symbolic_owner": str(bootstrap.get("owner") or ""),
                            "symbolic_name": str(bootstrap.get("name") or ""),
                            "symbolic_descriptor": str(bootstrap.get("descriptor") or ""),
                            "payload": bootstrap,
                        }
                        result.append(
                            BinaryFactStore._method_handle_with_loading_constraint_types(
                                bootstrap_edge, bootstrap
                            )
                        )
                    BinaryFactStore._collect_handles(constant.get("arguments") or (), handles)
                for index, handle in enumerate(handles):
                    handle_edge = {
                        "bytecode_offset": bci,
                        "edge_kind": f"ldc_bootstrap_handle_{index}",
                        "opcode": 18,
                        "symbolic_owner": str(handle.get("owner") or ""),
                        "symbolic_name": str(handle.get("name") or ""),
                        "symbolic_descriptor": str(handle.get("descriptor") or ""),
                        "payload": handle,
                    }
                    result.append(
                        BinaryFactStore._method_handle_with_loading_constraint_types(
                            handle_edge, handle
                        )
                    )
                if constant_kind == "handle":
                    result.extend(BinaryFactStore._method_handle_type_edges(
                        constant, bci, opcode=18
                    ))
                if constant_kind == "constant_dynamic":
                    result.extend(BinaryFactStore._field_descriptor_type_edges(
                        descriptor,
                        bci,
                        type_use_kind="constant_dynamic_descriptor",
                        opcode=18,
                    ))
                    bootstrap_handle = constant.get("bootstrap")
                    if (
                        isinstance(bootstrap_handle, dict)
                        and bootstrap_handle.get("kind") == "handle"
                    ):
                        result.extend(
                            BinaryFactStore._method_handle_type_edges(
                                bootstrap_handle, bci, opcode=18
                            )
                        )
                    for handle in handles:
                        result.extend(
                            BinaryFactStore._method_handle_type_edges(
                                handle, bci, opcode=18
                            )
                        )
                    result.extend(
                        BinaryFactStore._bootstrap_argument_type_edges(
                            constant.get("arguments") or (), bci
                        )
                    )
                return BinaryFactStore._deduplicate_type_edges(result)
        return []

    @staticmethod
    def _descriptor_owner(descriptor: str) -> str:
        value = str(descriptor or "")
        while value.startswith("["):
            value = value[1:]
        if value.startswith("L") and value.endswith(";"):
            return value[1:-1]
        return ""

    @staticmethod
    def _type_symbolic_owner(descriptor: str) -> str:
        """Preserve array/primitive class identities; unwrap only object L-types."""
        value = str(descriptor or "")
        if value.startswith("["):
            return value
        if value.startswith("L") and value.endswith(";"):
            return value[1:-1]
        return value

    @staticmethod
    def _method_descriptor_reference_owners(
        descriptor: str,
    ) -> tuple[str, ...]:
        """Return distinct object owners resolved by one CONSTANT_MethodType.

        Arrays resolve their object element class; primitive values and
        primitive arrays have no classfile provider.  The parser is kept in
        the production fact path and deliberately does not share the javap
        Oracle implementation.
        """
        value = str(descriptor or "")
        length = len(value)
        owners: list[str] = []
        seen: set[str] = set()

        def invalid() -> BinaryFactStoreError:
            return BinaryFactStoreError(
                "FACT_STORE_METHOD_TYPE_DESCRIPTOR_INVALID", value
            )

        def field_type(offset: int) -> tuple[int, int]:
            dimensions = 0
            while value[offset] == "[":
                dimensions += 1
                if dimensions > 255:
                    raise invalid()
                offset += 1
                if offset >= length:
                    raise invalid()
            marker = value[offset]
            if marker in "BCDFIJSZ":
                slots = 1 if dimensions or marker not in "JD" else 2
                return offset + 1, slots
            if marker != "L":
                raise invalid()
            end = value.find(";", offset + 1)
            if end < 0:
                raise invalid()
            owner = value[offset + 1:end]
            if (
                not owner
                or any(part == "" for part in owner.split("/"))
                or any(character in owner for character in ".[;")
            ):
                raise invalid()
            if owner not in seen:
                seen.add(owner)
                owners.append(owner)
            return end + 1, 1

        if length < 3 or value[0] != "(":
            raise invalid()
        cursor = 1
        parameter_slots = 0
        while cursor < length and value[cursor] != ")":
            cursor, slots = field_type(cursor)
            parameter_slots += slots
            if parameter_slots > 255:
                raise invalid()
        # The loop exits only at ')' or at the end of the descriptor.
        if cursor >= length:
            raise invalid()
        cursor += 1
        if cursor >= length:
            raise invalid()
        if value[cursor] == "V":
            cursor += 1
        else:
            cursor, _slots = field_type(cursor)
        if cursor != length:
            raise invalid()
        return tuple(owners)

    @staticmethod
    def _method_type_edges(
        constant: Mapping[str, Any], bci: int, *, opcode: int = 18,
    ) -> list[dict[str, Any]]:
        descriptor = str(constant.get("descriptor") or "")
        return [
            {
                "bytecode_offset": bci,
                "edge_kind": "type",
                "opcode": opcode,
                "symbolic_owner": owner,
                "symbolic_name": "<type>",
                "symbolic_descriptor": f"L{owner};",
                "payload": {
                    **constant,
                    "type_use_kind": "method_type_descriptor",
                    "referenced_type_descriptor": f"L{owner};",
                },
            }
            for owner in BinaryFactStore._method_descriptor_reference_owners(
                descriptor
            )
        ]

    @staticmethod
    def _method_descriptor_type_edges(
        descriptor: str,
        bci: int,
        *,
        type_use_kind: str,
        opcode: int,
    ) -> list[dict[str, Any]]:
        return [
            {
                "bytecode_offset": bci,
                "edge_kind": "type",
                "opcode": opcode,
                "symbolic_owner": owner,
                "symbolic_name": "<type>",
                "symbolic_descriptor": f"L{owner};",
                "payload": {
                    "descriptor": descriptor,
                    "type_use_kind": type_use_kind,
                    "referenced_type_descriptor": f"L{owner};",
                },
            }
            for owner in BinaryFactStore._method_descriptor_reference_owners(
                descriptor
            )
        ]

    @staticmethod
    def _member_reference_descriptor_owners(
        edge: Mapping[str, Any], *, member_kind: str,
    ) -> tuple[str, ...]:
        descriptor = str(edge.get("symbolic_descriptor") or "")
        try:
            if member_kind == "method":
                owners = BinaryFactStore._method_descriptor_reference_owners(
                    descriptor
                )
            elif member_kind == "field":
                owner = BinaryFactStore._field_descriptor_reference_owner(
                    descriptor
                )
                owners = (owner,) if owner else ()
            else:
                raise ValueError(member_kind)
        except (BinaryFactStoreError, TypeError, ValueError) as error:
            raise BinaryFactStoreError(
                "FACT_STORE_MEMBER_REFERENCE_DESCRIPTOR_INVALID",
                descriptor,
            ) from error
        # Loading constraints are a set over binary names. Canonical sorting
        # makes the compact declaration stable across descriptor order and
        # prevents duplicate parameter/return types from inflating storage.
        return tuple(sorted(set(owners)))

    @staticmethod
    def _with_loading_constraint_type_owners(
        edge: Mapping[str, Any], *, member_kind: str,
    ) -> dict[str, Any]:
        owners = BinaryFactStore._member_reference_descriptor_owners(
            edge, member_kind=member_kind
        )
        payload = dict(edge.get("payload") or {})
        if owners:
            payload[LOADING_CONSTRAINT_TYPE_OWNERS_KEY] = list(owners)
        else:
            payload.pop(LOADING_CONSTRAINT_TYPE_OWNERS_KEY, None)
        return {**edge, "payload": payload}

    @staticmethod
    def _method_handle_with_loading_constraint_types(
        edge: Mapping[str, Any], handle: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            tag = int(handle.get("tag") or 0)
        except (TypeError, ValueError) as error:
            raise BinaryFactStoreError(
                "FACT_STORE_METHOD_HANDLE_DESCRIPTOR_INVALID",
                str(handle.get("descriptor") or ""),
            ) from error
        reference_kind = METHOD_HANDLE_REFERENCE_KIND_BY_TAG.get(tag)
        if reference_kind is None:
            raise BinaryFactStoreError(
                "FACT_STORE_METHOD_HANDLE_DESCRIPTOR_INVALID",
                str(handle.get("descriptor") or ""),
            )
        try:
            return BinaryFactStore._with_loading_constraint_type_owners(
                edge,
                member_kind=(
                    "field" if tag in {1, 2, 3, 4} else "method"
                ),
            )
        except BinaryFactStoreError as error:
            raise BinaryFactStoreError(
                "FACT_STORE_METHOD_HANDLE_DESCRIPTOR_INVALID",
                str(handle.get("descriptor") or ""),
            ) from error

    @staticmethod
    def _field_descriptor_reference_owner(descriptor: str) -> str:
        value = str(descriptor or "")
        length = len(value)

        def invalid() -> BinaryFactStoreError:
            return BinaryFactStoreError(
                "FACT_STORE_FIELD_TYPE_DESCRIPTOR_INVALID", value
            )

        cursor = 0
        dimensions = 0
        while cursor < length and value[cursor] == "[":
            dimensions += 1
            if dimensions > 255:
                raise invalid()
            cursor += 1
        if cursor >= length:
            raise invalid()
        marker = value[cursor]
        if marker in "BCDFIJSZ":
            if cursor + 1 != length:
                raise invalid()
            return ""
        if marker != "L":
            raise invalid()
        end = value.find(";", cursor + 1)
        if end != length - 1:
            raise invalid()
        owner = value[cursor + 1:end]
        if (
            not owner
            or any(part == "" for part in owner.split("/"))
            or any(character in owner for character in ".[;")
        ):
            raise invalid()
        return owner

    @staticmethod
    def _field_descriptor_type_edges(
        descriptor: str,
        bci: int,
        *,
        type_use_kind: str,
        opcode: int,
    ) -> list[dict[str, Any]]:
        owner = BinaryFactStore._field_descriptor_reference_owner(descriptor)
        if not owner:
            return []
        return [{
            "bytecode_offset": bci,
            "edge_kind": "type",
            "opcode": opcode,
            "symbolic_owner": owner,
            "symbolic_name": "<type>",
            "symbolic_descriptor": f"L{owner};",
            "payload": {
                "descriptor": descriptor,
                "type_use_kind": type_use_kind,
                "referenced_type_descriptor": f"L{owner};",
            },
        }]

    @staticmethod
    def _method_handle_type_edges(
        handle: Mapping[str, Any], bci: int, *, opcode: int,
    ) -> list[dict[str, Any]]:
        descriptor = str(handle.get("descriptor") or "")
        try:
            tag = int(handle.get("tag") or 0)
            if tag in {1, 2, 3, 4}:
                edges = BinaryFactStore._field_descriptor_type_edges(
                    descriptor,
                    bci,
                    type_use_kind="method_handle_descriptor",
                    opcode=opcode,
                )
            elif tag in {5, 6, 7, 8, 9}:
                edges = BinaryFactStore._method_descriptor_type_edges(
                    descriptor,
                    bci,
                    type_use_kind="method_handle_descriptor",
                    opcode=opcode,
                )
            else:
                raise ValueError("invalid MethodHandle reference kind")
        except (BinaryFactStoreError, TypeError, ValueError) as error:
            raise BinaryFactStoreError(
                "FACT_STORE_METHOD_HANDLE_DESCRIPTOR_INVALID", descriptor
            ) from error
        return [
            {**edge, "payload": {**edge["payload"], "handle": dict(handle)}}
            for edge in edges
        ]

    @staticmethod
    def _bootstrap_argument_type_edges(
        value: Any, bci: int, *, opcode: int = 18,
    ) -> list[dict[str, Any]]:
        """Expand loadable Class/MethodType bootstrap constants recursively."""
        result: list[dict[str, Any]] = []
        pending = [value]
        while pending:
            candidate = pending.pop()
            if isinstance(candidate, (list, tuple)):
                # Reverse push preserves the original left-to-right DFS fact
                # order without allocating a self-recursive closure per
                # invokedynamic/ConstantDynamic instruction.
                pending.extend(reversed(candidate))
                continue
            if not isinstance(candidate, dict):
                continue
            constant_kind = str(candidate.get("kind") or "")
            if constant_kind == "method_type":
                result.extend(BinaryFactStore._method_type_edges(
                    candidate, bci, opcode=opcode
                ))
                continue
            if constant_kind == "type":
                descriptor = str(candidate.get("descriptor") or "")
                result.append({
                    "bytecode_offset": bci,
                    "edge_kind": "type",
                    "opcode": opcode,
                    "symbolic_owner": BinaryFactStore._type_symbolic_owner(
                        descriptor
                    ),
                    "symbolic_name": "<type>",
                    "symbolic_descriptor": descriptor,
                    "payload": {
                        **candidate,
                        "type_use_kind": "bootstrap_class_constant",
                    },
                })
                continue
            if constant_kind == "constant_dynamic":
                result.extend(BinaryFactStore._field_descriptor_type_edges(
                    str(candidate.get("descriptor") or ""),
                    bci,
                    type_use_kind="constant_dynamic_descriptor",
                    opcode=opcode,
                ))
                pending.append(candidate.get("arguments") or ())
        unique: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for edge in result:
            key = (
                str(edge["symbolic_owner"]),
                str(edge["payload"]["type_use_kind"]),
            )
            if key not in seen:
                seen.add(key)
                unique.append(edge)
        return unique

    @staticmethod
    def _deduplicate_type_edges(
        edges: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for edge in edges:
            if edge.get("edge_kind") != "type":
                result.append(edge)
                continue
            payload = edge.get("payload") or {}
            key = (
                str(edge.get("symbolic_owner") or ""),
                str(payload.get("type_use_kind") or ""),
            )
            if key not in seen:
                seen.add(key)
                result.append(edge)
        return result

    @staticmethod
    def _collect_handles(value: Any, output: list[dict[str, Any]]) -> None:
        pending = [value]
        while pending:
            candidate = pending.pop()
            if isinstance(candidate, dict):
                if candidate.get("kind") == "handle":
                    output.append(candidate)
                pending.extend(reversed(tuple(candidate.values())))
            elif isinstance(candidate, list):
                pending.extend(reversed(candidate))

    def add_reconciliation_record(
        self,
        *,
        analysis_context_identity: str,
        record_kind: str,
        status: str,
        subject_identity: str,
        payload: dict[str, Any],
    ) -> str:
        return self.add_reconciliation_records([{
            "analysis_context_identity": analysis_context_identity,
            "record_kind": record_kind,
            "status": status,
            "subject_identity": subject_identity,
            "payload": payload,
        }])[0]

    def add_reconciliation_records(
        self, records: Iterable[dict[str, Any]], *,
        collect_identities: bool = True,
    ) -> list[str]:
        def normalized_records():
            for raw in records:
                yield (
                    str(raw["analysis_context_identity"]),
                    str(raw["record_kind"]),
                    str(raw["status"]),
                    str(raw["subject_identity"]),
                    dict(raw["payload"]),
                )

        return self._add_normalized_reconciliation_records(
            normalized_records(), collect_identities=collect_identities
        )

    def add_reconciliation_payloads(
        self,
        *,
        analysis_context_identity: str,
        record_kind: str,
        records: Iterable[tuple[str, str, Mapping[str, Any]]],
        collect_identities: bool = True,
        manage_transaction: bool = True,
    ) -> list[str]:
        """Persist one internal record family without redundant envelopes.

        The reconciler already owns native dict payloads and one fixed context
        and kind per bounded chunk.  Keeping those values out of a temporary
        wrapper avoids a payload copy and two short-lived dictionaries for
        every runtime record; the stored envelope and identities remain byte
        identical to :meth:`add_reconciliation_records`. Internal bulk writers
        may disable transaction management only while an enclosing caller owns
        the SQLite transaction; the public default retains standalone
        atomicity.
        """
        context = str(analysis_context_identity)
        kind = str(record_kind)
        if not manage_transaction and not self.connection.in_transaction:
            raise BinaryFactStoreError(
                "FACT_STORE_RECONCILIATION_TRANSACTION_MISSING",
                "bulk reconciliation writes require an enclosing transaction",
            )
        if kind not in RECONCILIATION_KIND_CODES:
            raise BinaryFactStoreError(
                "FACT_STORE_RECONCILIATION_KIND_INVALID", kind
            )
        identities = []
        pending_identities: list[str] = []
        serialized = bytearray(b"[")
        context_json = _json(context).encode("utf-8")
        identity_prefix = (
            '{"namespace":' + _json(f"{kind}_record_identity")
            + ',"payload":'
        ).encode("utf-8")
        identity_suffix = b',"schema_version":"1"}'

        def next_chunk_ordinal() -> int:
            return int(self.connection.execute(
                "SELECT COALESCE(MAX(chunk_ordinal),-1)+1 "
                "FROM reconciliation_chunk_order WHERE record_kind=?",
                (RECONCILIATION_KIND_CODES[kind],),
            ).fetchone()[0])

        def flush() -> None:
            nonlocal serialized
            if not pending_identities:
                return
            serialized.extend(b"]")
            chunk_identity = _identity(
                "reconciliation_record_chunk_identity",
                {
                    "analysis_context_identity": context,
                    "record_kind": kind,
                    "record_identities": pending_identities,
                },
            )
            chunk_identity_bytes = bytes.fromhex(chunk_identity)
            self.connection.execute(
                "INSERT INTO reconciliation_records VALUES(?,?,?,?)",
                (
                    sqlite3.Binary(chunk_identity_bytes),
                    RECONCILIATION_KIND_CODES[kind],
                    len(pending_identities),
                    sqlite3.Binary(zlib.compress(serialized, level=1)),
                ),
            )
            self.connection.execute(
                "INSERT INTO reconciliation_chunk_order VALUES(?,?,?)",
                (
                    RECONCILIATION_KIND_CODES[kind],
                    next_chunk_ordinal(),
                    sqlite3.Binary(chunk_identity_bytes),
                ),
            )
            pending_identities.clear()
            serialized = bytearray(b"[")

        try:
            transaction = (
                self.connection if manage_transaction else nullcontext()
            )
            with transaction:
                existing = self.connection.execute(
                    "SELECT value FROM metadata WHERE key=?",
                    ("reconciliation_analysis_context_identity",),
                ).fetchone()
                if existing and existing[0] != context:
                    raise BinaryFactStoreError(
                        "FACT_STORE_RECONCILIATION_CONTEXT_CONFLICT",
                        f"{existing[0]} != {context}",
                    )
                self.connection.execute(
                    "INSERT OR IGNORE INTO metadata(key,value) VALUES(?,?)",
                    ("reconciliation_analysis_context_identity", context),
                )
                for status, subject_identity, raw_payload in records:
                    status = str(status)
                    subject_identity = str(subject_identity)
                    payload = (
                        raw_payload
                        if type(raw_payload) is dict
                        else dict(raw_payload)
                    )
                    payload_json = _json(payload).encode("utf-8")
                    status_json = _json(status).encode("utf-8")
                    subject_json = _json(subject_identity).encode("utf-8")
                    digest = hashlib.sha256(identity_prefix)
                    # Hash the canonical envelope in-place.  Concatenating it
                    # first copied every payload through several temporary
                    # ``bytes`` objects; at multi-million-edge scale that was
                    # pure memory bandwidth and allocator pressure.  These
                    # fragments are exactly the former canonical byte stream.
                    digest.update(b'{"analysis_context_identity":')
                    digest.update(context_json)
                    digest.update(b',"payload":')
                    digest.update(payload_json)
                    digest.update(b',"status":')
                    digest.update(status_json)
                    digest.update(b',"subject_identity":')
                    digest.update(subject_json)
                    digest.update(b"}")
                    digest.update(identity_suffix)
                    record_identity = digest.hexdigest()
                    if collect_identities:
                        identities.append(record_identity)
                    if pending_identities:
                        serialized.extend(b",")
                    serialized.extend(b'{"payload":')
                    serialized.extend(payload_json)
                    serialized.extend(b',"record_identity":"')
                    serialized.extend(record_identity.encode("ascii"))
                    serialized.extend(b'","status":')
                    serialized.extend(status_json)
                    serialized.extend(b',"subject_identity":')
                    serialized.extend(subject_json)
                    serialized.extend(b"}")
                    pending_identities.append(record_identity)
                    if len(pending_identities) >= 2_000:
                        flush()
                flush()
        except sqlite3.IntegrityError as error:
            raise BinaryFactStoreError(
                "FACT_STORE_RECONCILIATION_CONFLICT", str(error)
            ) from error
        return identities

    def _add_normalized_reconciliation_records(
        self,
        records: Iterable[tuple[str, str, str, str, Mapping[str, Any]]],
        *,
        collect_identities: bool,
    ) -> list[str]:
        identities = []
        context_identity = ""
        try:
            with self.connection:
                pending_kind = ""
                pending: list[dict[str, Any]] = []

                def flush() -> None:
                    nonlocal pending_kind, pending
                    if not pending:
                        return
                    chunk_identity = _identity(
                        "reconciliation_record_chunk_identity",
                        {
                            "analysis_context_identity": context_identity,
                            "record_kind": pending_kind,
                            "record_identities": [
                                item["record_identity"] for item in pending
                            ],
                        },
                    )
                    chunk_identity_bytes = bytes.fromhex(chunk_identity)
                    self.connection.execute(
                        "INSERT INTO reconciliation_records VALUES(?,?,?,?)",
                        (
                            sqlite3.Binary(chunk_identity_bytes),
                            RECONCILIATION_KIND_CODES[pending_kind],
                            len(pending),
                            sqlite3.Binary(zlib.compress(
                                _json(pending).encode("utf-8"), level=1
                            )),
                        ),
                    )
                    record_kind_code = RECONCILIATION_KIND_CODES[pending_kind]
                    chunk_ordinal = int(self.connection.execute(
                        "SELECT COALESCE(MAX(chunk_ordinal),-1)+1 "
                        "FROM reconciliation_chunk_order WHERE record_kind=?",
                        (record_kind_code,),
                    ).fetchone()[0])
                    self.connection.execute(
                        "INSERT INTO reconciliation_chunk_order VALUES(?,?,?)",
                        (
                            record_kind_code,
                            chunk_ordinal,
                            sqlite3.Binary(chunk_identity_bytes),
                        ),
                    )
                    pending_kind = ""
                    pending = []

                for (
                    analysis_context_identity,
                    record_kind,
                    status,
                    subject_identity,
                    payload,
                ) in records:
                    if record_kind not in RECONCILIATION_KIND_CODES:
                        raise BinaryFactStoreError(
                            "FACT_STORE_RECONCILIATION_KIND_INVALID", record_kind
                        )
                    if not context_identity:
                        context_identity = analysis_context_identity
                        existing = self.connection.execute(
                            "SELECT value FROM metadata WHERE key=?",
                            ("reconciliation_analysis_context_identity",),
                        ).fetchone()
                        if existing and existing[0] != context_identity:
                            raise BinaryFactStoreError(
                                "FACT_STORE_RECONCILIATION_CONTEXT_CONFLICT",
                                f"{existing[0]} != {context_identity}",
                            )
                        self.connection.execute(
                            "INSERT OR IGNORE INTO metadata(key,value) VALUES(?,?)",
                            ("reconciliation_analysis_context_identity", context_identity),
                        )
                    elif context_identity != analysis_context_identity:
                        raise BinaryFactStoreError(
                            "FACT_STORE_RECONCILIATION_CONTEXT_CONFLICT",
                            f"{context_identity} != {analysis_context_identity}",
                        )
                    record_identity = _identity(
                        f"{record_kind}_record_identity",
                        {
                            "analysis_context_identity": analysis_context_identity,
                            "status": status,
                            "subject_identity": subject_identity,
                            "payload": payload,
                        },
                    )
                    if collect_identities:
                        identities.append(record_identity)
                    if pending_kind and pending_kind != record_kind:
                        flush()
                    pending_kind = record_kind
                    pending.append({
                        "record_identity": record_identity,
                        "status": status,
                        "subject_identity": subject_identity,
                        "payload": payload,
                    })
                    if len(pending) >= 2_000:
                        flush()
                flush()
        except sqlite3.IntegrityError as error:
            raise BinaryFactStoreError(
                "FACT_STORE_RECONCILIATION_CONFLICT", str(error)
            ) from error
        return identities

    def add_source_overlay(
        self,
        *,
        overlay_identity: str,
        analysis_context_identity: str,
        binary_member_identity: str,
        mapping_status: str,
        source_location: Mapping[str, Any],
        conflict: Mapping[str, Any],
    ) -> None:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO source_overlays VALUES(?,?,?,?,?,?)",
                    (
                        overlay_identity,
                        analysis_context_identity,
                        binary_member_identity,
                        mapping_status,
                        _json(dict(source_location)),
                        _json(dict(conflict)),
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise BinaryFactStoreError(
                "FACT_STORE_SOURCE_OVERLAY_CONFLICT", str(error)
            ) from error

    def add_inline_overlay(self, record: dict[str, Any]) -> None:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO inline_overlays VALUES(?,?,?,?,?,?,?,?)",
                    (
                        record["inline_overlay_identity"],
                        record["analysis_context_identity"],
                        record["changed_field_member_identity"],
                        record.get("consumer_member_identity") or None,
                        record["consumption_state"],
                        record["binding_certainty"],
                        record["coverage_status"],
                        _json(record),
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise BinaryFactStoreError(
                "FACT_STORE_INLINE_OVERLAY_CONFLICT", str(error)
            ) from error

    def rows(
        self,
        table: str,
        *,
        where: str = "",
        parameters: Iterable[Any] = (),
        include_class_bytes: bool = True,
        include_class_facts: bool = True,
    ) -> list[dict[str, Any]]:
        """Return decoded rows, optionally omitting heavyweight class payloads.

        The historical API transparently expands both compressed classfile bytes
        and the full ASM fact document.  Metadata-only consumers must opt out so
        a table scan does not accidentally materialize every classfile twice in
        Python memory.
        """
        allowed = {
            "metadata", "artifact_instances", "archive_entries", "classes", "members",
            "direct_edges", "resources", "reconciliation_records",
            "reconciliation_chunk_order", "source_overlays", "inline_overlays",
        }
        if table not in allowed:
            raise BinaryFactStoreError("FACT_STORE_TABLE_INVALID", table)
        if table == "reconciliation_records" and where:
            raise BinaryFactStoreError(
                "FACT_STORE_RECONCILIATION_FILTER_UNSUPPORTED",
                "read and filter the transparently expanded records",
            )
        if table != "classes" and (
            not include_class_bytes or not include_class_facts
        ):
            raise BinaryFactStoreError(
                "FACT_STORE_CLASS_PAYLOAD_OPTION_INVALID", table
            )
        if table == "classes" and (
            not include_class_bytes or not include_class_facts
        ):
            columns = [
                str(row[1])
                for row in self.connection.execute("PRAGMA table_info(classes)")
                if (include_class_bytes or row[1] != "class_bytes_zlib")
                and (include_class_facts or row[1] != "fact_zlib")
            ]
            query = "SELECT " + ",".join(columns) + " FROM classes"
        else:
            query = f"SELECT * FROM {table}"
        if where:
            query += " WHERE " + where
        rows = [dict(row) for row in self.connection.execute(query, tuple(parameters))]
        if table == "classes":
            for row in rows:
                if include_class_bytes:
                    row["class_bytes"] = zlib.decompress(
                        row.pop("class_bytes_zlib")
                    )
                if include_class_facts:
                    row["fact_json"] = zlib.decompress(
                        row.pop("fact_zlib")
                    ).decode("utf-8")
        elif table == "reconciliation_records":
            context = self.connection.execute(
                "SELECT value FROM metadata WHERE key=?",
                ("reconciliation_analysis_context_identity",),
            ).fetchone()
            expanded = []
            for row in rows:
                kind = RECONCILIATION_CODE_KINDS[int(row["record_kind"])]
                records = json.loads(
                    zlib.decompress(row["payload_zlib"]).decode("utf-8")
                )
                if len(records) != int(row["record_count"]):
                    raise BinaryFactStoreError(
                        "FACT_STORE_RECONCILIATION_CHUNK_COUNT_INVALID",
                        bytes(row["chunk_identity"]).hex(),
                    )
                expanded.extend({
                    "record_identity": envelope["record_identity"],
                    "analysis_context_identity": context[0] if context else "",
                    "record_kind": kind,
                    "status": envelope["status"],
                    "subject_identity": envelope["subject_identity"],
                    "payload_json": _json(envelope["payload"]),
                } for envelope in records)
            rows = expanded
        return rows

    def reconciliation_payloads(
        self, record_kind: str
    ) -> Iterator[dict[str, Any]]:
        """Yield one persisted reconciliation kind a chunk at a time.

        Selective in-memory reconciliation can later hydrate only the evidence
        required by a real trace graph. Filtering at the compact chunk table
        avoids expanding every other reconciliation family as a side effect.
        """

        kind = str(record_kind or "")
        code = RECONCILIATION_KIND_CODES.get(kind)
        if code is None:
            raise BinaryFactStoreError(
                "FACT_STORE_RECONCILIATION_KIND_INVALID", kind
            )
        ordered_chunks = self.connection.execute(
            """
            SELECT records.chunk_identity,records.record_count,
                   records.payload_zlib
            FROM reconciliation_chunk_order AS ordering
            JOIN reconciliation_records AS records
              ON records.chunk_identity=ordering.chunk_identity
             AND records.record_kind=ordering.record_kind
            WHERE ordering.record_kind=?
            ORDER BY ordering.chunk_ordinal
            """,
            (code,),
        )
        unordered_chunks = self.connection.execute(
            """
            SELECT records.chunk_identity,records.record_count,
                   records.payload_zlib
            FROM reconciliation_records AS records
            LEFT JOIN reconciliation_chunk_order AS ordering
              ON ordering.chunk_identity=records.chunk_identity
             AND ordering.record_kind=records.record_kind
            WHERE records.record_kind=?
              AND ordering.chunk_identity IS NULL
            ORDER BY records.chunk_identity
            """,
            (code,),
        )
        # The ordinal is a locality hint only. Corrupting or deleting one hint
        # changes traversal order but can never make persisted evidence vanish.
        for row in chain(ordered_chunks, unordered_chunks):
            records = json.loads(
                zlib.decompress(row["payload_zlib"]).decode("utf-8")
            )
            if len(records) != int(row["record_count"]):
                raise BinaryFactStoreError(
                    "FACT_STORE_RECONCILIATION_CHUNK_COUNT_INVALID",
                    bytes(row["chunk_identity"]).hex(),
                )
            for envelope in records:
                yield dict(envelope["payload"])

    def reconciliation_payload_count(self, record_kind: str) -> int:
        """Return a persisted family count without expanding its chunks."""

        kind = str(record_kind or "")
        code = RECONCILIATION_KIND_CODES.get(kind)
        if code is None:
            raise BinaryFactStoreError(
                "FACT_STORE_RECONCILIATION_KIND_INVALID", kind
            )
        return int(self.connection.execute(
            """
            SELECT COALESCE(SUM(record_count),0)
            FROM reconciliation_records
            WHERE record_kind=?
            """,
            (code,),
        ).fetchone()[0])

    def class_bytes(self, class_variant_identity: str) -> bytes:
        """Load one classfile payload by identity without expanding its fact row."""
        row = self.connection.execute(
            "SELECT class_bytes_zlib FROM classes WHERE class_variant_identity=?",
            (str(class_variant_identity),),
        ).fetchone()
        if row is None:
            raise BinaryFactStoreError(
                "FACT_STORE_CLASS_VARIANT_MISSING", str(class_variant_identity)
            )
        return zlib.decompress(row[0])

    @staticmethod
    def _empty_runtime_trigger_summary() -> dict[str, Any]:
        return {
            "has_runtime_annotations": False,
            "hierarchy_types": frozenset(),
            "has_main_method": False,
        }

    @staticmethod
    def _validated_runtime_trigger_summary(
        value: Any,
    ) -> dict[str, Any]:
        if (
            not isinstance(value, Mapping)
            or set(value) != _RUNTIME_TRIGGER_SUMMARY_FIELDS
            or type(value.get("has_runtime_annotations")) is not bool
            or type(value.get("has_main_method")) is not bool
            or not isinstance(value.get("hierarchy_types"), frozenset)
            or not all(
                isinstance(item, str) and bool(item)
                for item in value["hierarchy_types"]
            )
        ):
            raise BinaryFactStoreError(
                "FACT_STORE_RUNTIME_TRIGGER_SUMMARY_INVALID",
                "runtime trigger summary has an invalid shape",
            )
        return {
            "has_runtime_annotations": value[
                "has_runtime_annotations"
            ],
            "hierarchy_types": frozenset(value["hierarchy_types"]),
            "has_main_method": value["has_main_method"],
        }

    @staticmethod
    def _runtime_trigger_summary_copy(
        value: Mapping[str, Any],
    ) -> dict[str, Any]:
        return BinaryFactStore._validated_runtime_trigger_summary(value)

    def _runtime_trigger_data_version(self) -> int:
        row = self.connection.execute("PRAGMA data_version").fetchone()
        if row is None or type(row[0]) is not int or int(row[0]) < 0:
            raise BinaryFactStoreError(
                "FACT_STORE_RUNTIME_TRIGGER_DATA_VERSION_INVALID",
                str(row[0] if row is not None else "missing"),
            )
        return int(row[0])

    def adopt_runtime_trigger_summary_from_exact_backup(
        self,
        source: "BinaryFactStore",
    ) -> dict[str, Any]:
        """Adopt a source cache only after an exact SQLite backup.

        ``sqlite3.Connection.backup`` replaces database bytes through the
        destination connection itself, so SQLite's cross-connection
        ``data_version`` does not change.  The destination therefore cannot
        discover that its prior empty cache is stale.  This explicit protocol
        validates the source, the summary shape and every persisted fact-table
        count before installing a defensive copy.
        """

        if not isinstance(source, BinaryFactStore) or source is self:
            raise BinaryFactStoreError(
                "FACT_STORE_RUNTIME_TRIGGER_BACKUP_SOURCE_INVALID",
                type(source).__name__,
            )
        try:
            source_version_before = source._runtime_trigger_data_version()
            destination_version_before = (
                self._runtime_trigger_data_version()
            )
            source_summary = self._validated_runtime_trigger_summary(
                source.runtime_trigger_summary()
            )
            source_counts = source.counts()
            destination_counts = self.counts()
            source_version_after = source._runtime_trigger_data_version()
            destination_version_after = (
                self._runtime_trigger_data_version()
            )
        except BinaryFactStoreError:
            raise
        except (sqlite3.Error, TypeError, ValueError) as error:
            raise BinaryFactStoreError(
                "FACT_STORE_RUNTIME_TRIGGER_BACKUP_INVALID",
                str(error),
            ) from error
        if (
            source_version_before != source_version_after
            or destination_version_before != destination_version_after
        ):
            raise BinaryFactStoreError(
                "FACT_STORE_RUNTIME_TRIGGER_BACKUP_UNSTABLE",
                "source or destination changed during summary adoption",
            )
        if source_counts != destination_counts:
            raise BinaryFactStoreError(
                "FACT_STORE_RUNTIME_TRIGGER_BACKUP_MISMATCH",
                _json({
                    "source_counts": source_counts,
                    "destination_counts": destination_counts,
                }),
            )
        self._runtime_trigger_summary_cache = source_summary
        self._runtime_trigger_summary_data_version = (
            destination_version_after
        )
        return self._runtime_trigger_summary_copy(source_summary)

    @staticmethod
    def _runtime_trigger_fact_components(
        fact: Mapping[str, Any],
        *,
        include_main_method: bool,
    ) -> tuple[bool, tuple[str, ...], bool]:
        methods = fact.get("methods") or ()
        has_runtime_annotations = bool(fact.get("annotations")) or any(
            (field or {}).get("annotations")
            for field in fact.get("fields") or ()
        ) or any(
            ((method or {}).get("contract") or {}).get("annotations")
            for method in methods
        )
        hierarchy_types = tuple(
            str(value)
            for value in (
                fact.get("super_name"),
                *(fact.get("interfaces") or ()),
            )
            if value
        )
        has_main_method = False
        if include_main_method:
            for method in methods:
                contract = (method or {}).get("contract") or {}
                if (
                    str(contract.get("name") or "") == "main"
                    and str(contract.get("descriptor") or "")
                    == "([Ljava/lang/String;)V"
                ):
                    has_main_method = True
                    break
        return has_runtime_annotations, hierarchy_types, has_main_method

    def runtime_trigger_summary(self) -> dict[str, Any]:
        """Return a bounded-memory preflight for semantic/entrypoint builders.

        The full builders require parsed ASM facts for selected classes. Most
        dependencies have no runtime-visible annotations or callback hierarchy
        at all, so retaining every parsed fact merely to produce an empty
        overlay is avoidable. The exact trigger fields are normalized beside
        the compressed fact, allowing reopened and SQLite-rebound stores to
        recover the summary without inflating every ASM document.
        """

        current_data_version = self._runtime_trigger_data_version()
        cached = self._runtime_trigger_summary_cache
        if (
            cached is not None
            and self._runtime_trigger_summary_data_version
            == current_data_version
        ):
            return self._runtime_trigger_summary_copy(cached)
        self._runtime_trigger_summary_cache = None
        self._runtime_trigger_summary_data_version = None
        observed_versions: list[tuple[int, int]] = []
        for _attempt in range(_RUNTIME_TRIGGER_SUMMARY_SCAN_ATTEMPTS):
            version_before = self._runtime_trigger_data_version()
            has_annotations = False
            hierarchy_types: set[str] = set()
            for raw in self.connection.execute(
                "SELECT has_runtime_annotations,super_name,interfaces_json "
                "FROM classes"
            ):
                has_annotations = has_annotations or bool(raw[0])
                hierarchy_types.update(
                    str(value)
                    for value in (
                        raw[1],
                        *(json.loads(raw[2]) if raw[2] != "[]" else ()),
                    )
                    if value
                )
            has_main_method = self.connection.execute(
                """
                SELECT 1 FROM members
                WHERE member_kind='method' AND member_name='main'
                  AND descriptor='([Ljava/lang/String;)V'
                LIMIT 1
                """
            ).fetchone() is not None
            version_after = self._runtime_trigger_data_version()
            observed_versions.append((version_before, version_after))
            if version_before != version_after:
                continue
            result = self._validated_runtime_trigger_summary({
                "has_runtime_annotations": has_annotations,
                "hierarchy_types": frozenset(hierarchy_types),
                "has_main_method": has_main_method,
            })
            self._runtime_trigger_summary_cache = result
            self._runtime_trigger_summary_data_version = version_after
            return self._runtime_trigger_summary_copy(result)
        raise BinaryFactStoreError(
            "FACT_STORE_RUNTIME_TRIGGER_SUMMARY_UNSTABLE",
            _json({"observed_data_versions": observed_versions}),
        )

    def counts(self) -> dict[str, int]:
        tables = (
            "artifact_instances", "archive_entries", "classes", "members", "direct_edges",
            "resources", "reconciliation_records", "reconciliation_chunk_order",
            "source_overlays", "inline_overlays",
        )
        result = {
            table: int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        }
        result["reconciliation_records"] = int(
            self.connection.execute(
                "SELECT COALESCE(SUM(record_count),0) FROM reconciliation_records"
            ).fetchone()[0]
        )
        return result

    def content_identity(self) -> str:
        """Hash persisted table content with memory bounded to one SQLite row.

        This diagnostic identity is intentionally based on exact persisted
        values in primary-key order.  Binary blobs are represented by digest
        and byte length, so class bytes, facts, and reconciliation chunks are
        never decompressed or accumulated merely to compare test stores.
        """

        tables = (
            "artifact_instances", "archive_entries", "classes", "members", "direct_edges",
            "resources", "reconciliation_records", "reconciliation_chunk_order",
            "source_overlays", "inline_overlays",
        )

        def rows(table: str) -> Iterator[dict[str, Any]]:
            columns = [
                (str(item[1]), int(item[5]))
                for item in self.connection.execute(
                    f"PRAGMA table_info({table})"
                )
            ]
            primary_key = [
                name for name, position in sorted(
                    columns, key=lambda item: item[1] or 1_000_000
                )
                if position
            ]
            if not primary_key:
                raise BinaryFactStoreError(
                    "FACT_STORE_CONTENT_IDENTITY_ORDER_MISSING", table
                )
            order = ",".join(f'"{name}"' for name in primary_key)
            cursor = self.connection.execute(
                f"SELECT * FROM {table} ORDER BY {order}"
            )
            try:
                for raw in cursor:
                    yield {
                        key: (
                            {
                                "blob_sha256": hashlib.sha256(value).hexdigest(),
                                "byte_length": len(value),
                            }
                            if isinstance(value, bytes) else value
                        )
                        for key, value in dict(raw).items()
                    }
            finally:
                cursor.close()

        payload = {
            "schema_version": SCHEMA_VERSION,
            "tables": {
                table: StreamingCanonicalSequence(
                    lambda table=table: rows(table)
                )
                for table in tables
            },
        }
        return canonical_identity_streaming(
            "binary_fact_store_content_identity",
            payload,
            schema_version="1",
        )


__all__ = [
    "BinaryFactStore", "BinaryFactStoreError",
    "SCHEMA_VERSION",
    "RECONCILIATION_KIND_CODES",
]
