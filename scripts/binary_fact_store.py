#!/usr/bin/env python3
"""ArtifactInstance-keyed SQLite store for ASM binary facts."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable, Iterator
import zlib

from binary_artifact_diff import ArtifactSnapshot
from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_first_model import ArtifactInstance


SCHEMA_VERSION = "binary-fact-sqlite-v3"
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
RECONCILIATION_CODE_KINDS = {
    value: key for key, value in RECONCILIATION_KIND_CODES.items()
}


class BinaryFactStoreError(BinaryFirstContractError):
    pass


def _json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


class BinaryFactStore:
    FACT_INSERT_CHUNK_SIZE = 2_000

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        defer_secondary_indexes: bool = False,
        bulk_load_transaction: bool = False,
    ):
        self.path = str(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self._runtime_trigger_summary_cache: dict[str, Any] | None = None
        self._bulk_load_transaction = False
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=MEMORY")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self._create_schema()
        if not defer_secondary_indexes:
            self.ensure_secondary_indexes()
        self._bulk_load_transaction = bool(bulk_load_transaction)
        if self._bulk_load_transaction:
            self.connection.execute("BEGIN")

    def close(self):
        self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def _create_schema(self):
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
                edge_json TEXT NOT NULL,
                UNIQUE(caller_member_identity, bytecode_offset, instruction_index, edge_kind)
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
        self._runtime_trigger_summary_cache = None
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
                    "INSERT INTO archive_entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                            entry.multi_release_version,
                            entry.resource_category,
                            entry.normalized_resource_digest,
                            _json(entry.resource_semantic_facts),
                            _json(asdict(entry)),
                        )
                        for entry in snapshot.entries
                    ),
                )
                counts["entries"] = len(snapshot.entries)
                resource_entries = tuple(
                    entry for entry in snapshot.entries
                    if entry.kind == "resource"
                )
                self.connection.executemany(
                    "INSERT INTO resources VALUES(?,?,?,?,?,?,?)",
                    (
                        (
                            entry.physical_entry_identity,
                            instance.identity,
                            entry.name,
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
                    self.connection.executemany(
                        "INSERT INTO classes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        class_rows,
                    )
                    self.connection.executemany(
                        "INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?)",
                        member_rows,
                    )
                    self.connection.executemany(
                        "INSERT INTO direct_edges VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        edge_rows,
                    )
                    class_rows.clear()
                    member_rows.clear()
                    edge_rows.clear()

                for record in snapshot.class_records:
                    label = str(record.get("class_entry") or "")
                    entry = entry_by_label.get(label)
                    if entry is None:
                        raise BinaryFactStoreError(
                            "FACT_STORE_CLASS_ENTRY_UNBOUND", label
                        )
                    parse_status = (
                        "parsed" if record.get("frame_type") == "class_fact" else "failed"
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
                    class_payload = payload_by_label.get(label)
                    if class_payload is None:
                        raise BinaryFactStoreError(
                            "FACT_STORE_CLASS_PAYLOAD_UNBOUND", label
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
                            sqlite3.Binary(zlib.compress(class_payload, level=1)),
                            sqlite3.Binary(zlib.compress(
                                _json(record).encode("utf-8"), level=1
                            )),
                        )
                    )
                    counts["classes"] += 1
                    if parse_status != "parsed":
                        if len(class_rows) >= self.FACT_INSERT_CHUNK_SIZE:
                            flush_fact_rows()
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
                        for instruction_index, instruction in enumerate(method.get("instructions") or ()):
                            for edge in self._instruction_edges(instruction):
                                edge_identity = _identity(
                                    "binary_direct_edge_identity",
                                    {
                                        "caller_member_identity": member_identity,
                                        "bytecode_offset": edge["bytecode_offset"],
                                        "instruction_index": instruction_index,
                                        "edge_kind": edge["edge_kind"],
                                        "symbolic_owner": edge["symbolic_owner"],
                                        "symbolic_name": edge["symbolic_name"],
                                        "symbolic_descriptor": edge["symbolic_descriptor"],
                                        "edge_payload": edge["payload"],
                                    },
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
                                        _json(edge["payload"]),
                                    )
                                )
                                counts["edges"] += 1
                    # Keep temporary insert tuples bounded for unusually large
                    # monolithic archives while still crossing the Python/C
                    # boundary in useful batches.
                    if len(class_rows) >= self.FACT_INSERT_CHUNK_SIZE:
                        flush_fact_rows()
                flush_fact_rows()
        except sqlite3.IntegrityError as error:
            if self._bulk_load_transaction:
                self.connection.rollback()
                self._bulk_load_transaction = False
            raise BinaryFactStoreError(
                "FACT_STORE_IDENTITY_CONFLICT", str(error)
            ) from error
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
            handles = []
            BinaryFactStore._collect_handles(instruction[5], handles)
            for index, handle in enumerate(handles):
                result.append({
                    "bytecode_offset": bci,
                    "edge_kind": f"invokedynamic_handle_{index}",
                    "opcode": 186,
                    "symbolic_owner": str(handle.get("owner") or ""),
                    "symbolic_name": str(handle.get("name") or ""),
                    "symbolic_descriptor": str(handle.get("descriptor") or ""),
                    "payload": handle,
                })
            return result
        if kind == "ldc" and len(instruction) >= 3 and isinstance(instruction[2], dict):
            constant = instruction[2]
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
                handles = []
                if constant_kind == "constant_dynamic":
                    bootstrap = constant.get("bootstrap")
                    if isinstance(bootstrap, dict) and bootstrap.get("kind") == "handle":
                        result.append({
                            "bytecode_offset": bci,
                            "edge_kind": "ldc_constant_dynamic_bootstrap",
                            "opcode": 18,
                            "symbolic_owner": str(bootstrap.get("owner") or ""),
                            "symbolic_name": str(bootstrap.get("name") or ""),
                            "symbolic_descriptor": str(bootstrap.get("descriptor") or ""),
                            "payload": bootstrap,
                        })
                    BinaryFactStore._collect_handles(constant.get("arguments") or (), handles)
                for index, handle in enumerate(handles):
                    result.append({
                        "bytecode_offset": bci,
                        "edge_kind": f"ldc_bootstrap_handle_{index}",
                        "opcode": 18,
                        "symbolic_owner": str(handle.get("owner") or ""),
                        "symbolic_name": str(handle.get("name") or ""),
                        "symbolic_descriptor": str(handle.get("descriptor") or ""),
                        "payload": handle,
                    })
                return result
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
    def _collect_handles(value: Any, output: list[dict[str, Any]]) -> None:
        if isinstance(value, dict):
            if value.get("kind") == "handle":
                output.append(value)
            for nested in value.values():
                BinaryFactStore._collect_handles(nested, output)
        elif isinstance(value, list):
            for nested in value:
                BinaryFactStore._collect_handles(nested, output)

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
                    self.connection.execute(
                        "INSERT INTO reconciliation_records VALUES(?,?,?,?)",
                        (
                            sqlite3.Binary(bytes.fromhex(chunk_identity)),
                            RECONCILIATION_KIND_CODES[pending_kind],
                            len(pending),
                            sqlite3.Binary(zlib.compress(
                                _json(pending).encode("utf-8"), level=1
                            )),
                        ),
                    )
                    pending_kind = ""
                    pending = []

                for raw in records:
                    analysis_context_identity = str(
                        raw["analysis_context_identity"]
                    )
                    record_kind = str(raw["record_kind"])
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
                    status = str(raw["status"])
                    subject_identity = str(raw["subject_identity"])
                    payload = dict(raw["payload"])
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
            "direct_edges", "resources", "reconciliation_records", "source_overlays",
            "inline_overlays",
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
        for row in self.connection.execute(
            """
            SELECT chunk_identity,record_count,payload_zlib
            FROM reconciliation_records
            WHERE record_kind=?
            ORDER BY chunk_identity
            """,
            (code,),
        ):
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

    def runtime_trigger_summary(self) -> dict[str, Any]:
        """Return a bounded-memory preflight for semantic/entrypoint builders.

        The full builders require parsed ASM facts for selected classes. Most
        dependencies have no runtime-visible annotations or callback hierarchy
        at all, so retaining every parsed fact merely to produce an empty
        overlay is avoidable. This scan keeps only a small hierarchy-name set
        and stops retaining each decompressed document immediately.
        """

        cached = self._runtime_trigger_summary_cache
        if cached is not None:
            return cached
        has_annotations = False
        hierarchy_types: set[str] = set()
        for raw in self.connection.execute("SELECT fact_zlib FROM classes"):
            fact = json.loads(zlib.decompress(raw[0]).decode("utf-8"))
            hierarchy_types.update(
                str(value)
                for value in (
                    fact.get("super_name"),
                    *(fact.get("interfaces") or ()),
                )
                if value
            )
            if fact.get("annotations"):
                has_annotations = True
                break
            if any(
                (field or {}).get("annotations")
                for field in fact.get("fields") or ()
            ):
                has_annotations = True
                break
            if any(
                ((method or {}).get("contract") or {}).get("annotations")
                for method in fact.get("methods") or ()
            ):
                has_annotations = True
                break
        has_main_method = self.connection.execute(
            """
            SELECT 1 FROM members
            WHERE member_kind='method' AND member_name='main'
              AND descriptor='([Ljava/lang/String;)V'
            LIMIT 1
            """
        ).fetchone() is not None
        result = {
            "has_runtime_annotations": has_annotations,
            "hierarchy_types": frozenset(hierarchy_types),
            "has_main_method": has_main_method,
        }
        self._runtime_trigger_summary_cache = result
        return result

    def counts(self) -> dict[str, int]:
        tables = (
            "artifact_instances", "archive_entries", "classes", "members", "direct_edges",
            "resources", "reconciliation_records", "source_overlays",
            "inline_overlays",
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
        payload = {"schema_version": SCHEMA_VERSION, "tables": {}}
        for table in (
            "artifact_instances", "archive_entries", "classes", "members", "direct_edges",
            "resources", "reconciliation_records", "source_overlays",
            "inline_overlays",
        ):
            rows = [
                {
                    key: (
                        {
                            "blob_sha256": hashlib.sha256(value).hexdigest(),
                            "byte_length": len(value),
                        }
                        if isinstance(value, bytes) else value
                    )
                    for key, value in row.items()
                }
                for row in self.rows(table)
            ]
            payload["tables"][table] = sorted(
                rows,
                key=lambda item: _json(item),
            )
        return _identity("binary_fact_store_content_identity", payload)


__all__ = [
    "BinaryFactStore", "BinaryFactStoreError", "SCHEMA_VERSION",
    "RECONCILIATION_KIND_CODES",
]
