#!/usr/bin/env python3
"""ArtifactInstance-keyed SQLite store for ASM binary facts."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable

from binary_artifact_diff import ArtifactSnapshot
from binary_first_contract import BinaryFirstContractError, canonical_identity
from binary_first_model import ArtifactInstance


SCHEMA_VERSION = "binary-fact-sqlite-v2"


class BinaryFactStoreError(BinaryFirstContractError):
    pass


def _json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _identity(namespace: str, payload: Any) -> str:
    return canonical_identity(namespace, payload, schema_version="1")


class BinaryFactStore:
    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=MEMORY")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self._create_schema()

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
            CREATE INDEX IF NOT EXISTS artifact_instances_coord
                ON artifact_instances(coord);
            CREATE INDEX IF NOT EXISTS artifact_instances_runtime_slot
                ON artifact_instances(runtime_profile_identity, loader_realm_identity, runtime_classpath_index);

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
            CREATE INDEX IF NOT EXISTS archive_entries_class
                ON archive_entries(artifact_instance_identity, logical_class_entry, multi_release_version);

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
                class_bytes BLOB NOT NULL,
                fact_json TEXT NOT NULL,
                UNIQUE(artifact_instance_identity, physical_entry_label)
            );
            CREATE INDEX IF NOT EXISTS classes_runtime_lookup
                ON classes(artifact_instance_identity, class_name, multi_release_version);

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
            CREATE INDEX IF NOT EXISTS members_symbolic_lookup
                ON members(class_name, member_kind, member_name, descriptor);

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
            CREATE INDEX IF NOT EXISTS direct_edges_symbolic_target
                ON direct_edges(symbolic_owner, symbolic_name, symbolic_descriptor);

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
                record_identity TEXT PRIMARY KEY,
                analysis_context_identity TEXT NOT NULL,
                record_kind TEXT NOT NULL,
                status TEXT NOT NULL,
                subject_identity TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS reconciliation_records_context_kind
                ON reconciliation_records(analysis_context_identity, record_kind, subject_identity);

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
        entry_by_label = {
            f"{item.name}#occurrence={item.name_ordinal}": item
            for item in snapshot.entries
        }
        payload_by_label = dict(snapshot.class_payloads)
        counts = {"entries": 0, "classes": 0, "members": 0, "edges": 0, "resources": 0}
        try:
            with self.connection:
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
                        snapshot.comparison_coverage_status,
                    ),
                )
                for entry in snapshot.entries:
                    self.connection.execute(
                        "INSERT INTO archive_entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                        ),
                    )
                    counts["entries"] += 1
                    if entry.kind == "resource":
                        self.connection.execute(
                            "INSERT INTO resources VALUES(?,?,?,?,?,?,?)",
                            (
                                entry.physical_entry_identity,
                                instance.identity,
                                entry.name,
                                entry.resource_category,
                                entry.content_sha256,
                                entry.normalized_resource_digest,
                                _json(entry.resource_semantic_facts),
                            ),
                        )
                        counts["resources"] += 1

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
                    self.connection.execute(
                        "INSERT INTO classes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                            sqlite3.Binary(class_payload),
                            _json(record),
                        ),
                    )
                    counts["classes"] += 1
                    if parse_status != "parsed":
                        continue
                    for field in record.get("fields") or ():
                        self._insert_member(
                            variant_identity,
                            instance.identity,
                            class_name,
                            "field",
                            field,
                            "",
                        )
                        counts["members"] += 1
                    for method in record.get("methods") or ():
                        contract = method.get("contract") or {}
                        member_identity = self._insert_member(
                            variant_identity,
                            instance.identity,
                            class_name,
                            "method",
                            contract,
                            str(method.get("implementation_digest") or ""),
                        )
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
                                self.connection.execute(
                                    "INSERT INTO direct_edges VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
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
                                    ),
                                )
                                counts["edges"] += 1
        except sqlite3.IntegrityError as error:
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
        self.connection.execute(
            "INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
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
            ),
        )
        return member_identity

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
                "symbolic_owner": BinaryFactStore._descriptor_owner(descriptor),
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
                    owner = BinaryFactStore._descriptor_owner(descriptor)
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
        record_identity = _identity(
            f"{record_kind}_record_identity",
            {
                "analysis_context_identity": analysis_context_identity,
                "status": status,
                "subject_identity": subject_identity,
                "payload": payload,
            },
        )
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO reconciliation_records VALUES(?,?,?,?,?,?)",
                    (
                        record_identity,
                        analysis_context_identity,
                        record_kind,
                        status,
                        subject_identity,
                        _json(payload),
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise BinaryFactStoreError(
                "FACT_STORE_RECONCILIATION_CONFLICT", str(error)
            ) from error
        return record_identity

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

    def rows(self, table: str, *, where: str = "", parameters: Iterable[Any] = ()) -> list[dict[str, Any]]:
        allowed = {
            "metadata", "artifact_instances", "archive_entries", "classes", "members",
            "direct_edges", "resources", "reconciliation_records", "source_overlays",
            "inline_overlays",
        }
        if table not in allowed:
            raise BinaryFactStoreError("FACT_STORE_TABLE_INVALID", table)
        query = f"SELECT * FROM {table}"
        if where:
            query += " WHERE " + where
        return [dict(row) for row in self.connection.execute(query, tuple(parameters))]

    def counts(self) -> dict[str, int]:
        tables = (
            "artifact_instances", "archive_entries", "classes", "members", "direct_edges",
            "resources", "reconciliation_records", "source_overlays",
            "inline_overlays",
        )
        return {
            table: int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        }

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


__all__ = ["BinaryFactStore", "BinaryFactStoreError", "SCHEMA_VERSION"]
