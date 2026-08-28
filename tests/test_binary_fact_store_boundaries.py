import json
from pathlib import Path
from types import SimpleNamespace
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zlib


ROOT_DIR = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_fact_store as facts  # noqa: E402


class Result:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class VersionConnection:
    def __init__(self, row):
        self.row = row

    def execute(self, _query):
        return Result(self.row)


class BinaryFactStoreBoundaryTest(unittest.TestCase):
    @staticmethod
    def _instance(identity="instance", content="content"):
        return SimpleNamespace(
            identity=identity,
            coord="coord",
            outer_artifact_sha256="outer",
            container_entry="<artifact>",
            content_sha256=content,
            runtime_profile_identity="runtime",
            path_owner_loader_realm_identity="loader",
            runtime_path_kind="classpath",
            runtime_classpath_index=0,
            container_loader_policy_version="policy",
            runtime_code_source_origin_identity="origin",
        )

    @staticmethod
    def _entry(name, ordinal, *, kind="class", effective=False):
        return SimpleNamespace(
            physical_entry_identity=f"entry-{name}-{ordinal}",
            name=name,
            name_ordinal=ordinal,
            archive_ordinal=ordinal,
            kind=kind,
            content_sha256=f"sha-{name}-{ordinal}",
            byte_length=1,
            crc32=0,
            compression_method=0,
            compressed_size=1,
            timestamp=(1980, 1, 1, 0, 0, 0),
            external_attributes=0,
            extra_sha256="",
            comment_sha256="",
            logical_class_entry=name if kind == "class" else "",
            logical_resource_entry="" if kind == "resource" else "",
            multi_release_version=0,
            runtime_effective=effective,
            resource_category="other",
            normalized_resource_digest="normalized",
            resource_semantic_facts=(),
        )

    @staticmethod
    def _snapshot(entries=(), records=(), payloads=(), *, identity="instance", content="content"):
        return SimpleNamespace(
            artifact_instance_identity=identity,
            artifact_content_sha256=content,
            entries=tuple(entries),
            class_records=tuple(records),
            class_payloads=tuple(payloads),
            inventory_digest="inventory",
            parser_identity="parser",
            class_fact_coverage_status="complete",
        )

    def test_member_value_normalization_matrix(self):
        identity, values = facts.BinaryFactStore._member_values(
            "variant", "artifact", "Owner", "method", {}, ""
        )
        self.assertEqual(len(identity), 64)
        self.assertEqual(values[5:8], ("", "", 0))
        identity_two, full = facts.BinaryFactStore._member_values(
            "variant", "artifact", "Owner", "field",
            {"name": "VALUE", "descriptor": "I", "access": 9}, "digest",
        )
        self.assertNotEqual(identity, identity_two)
        self.assertEqual(full[5:8], ("VALUE", "I", 9))

    def test_instruction_edge_shape_and_static_initialization_matrix(self):
        for invalid in (None, (), [], ["method"], ["method", "bad"]):
            with self.subTest(invalid=invalid):
                self.assertEqual(facts.BinaryFactStore._instruction_edges(invalid), [])

        method = facts.BinaryFactStore._instruction_edges(
            ["method", 1, 182, "pkg/Owner", "run", "(Ljava/lang/String;)V", True]
        )
        self.assertEqual([row["edge_kind"] for row in method], ["method"])
        self.assertEqual(
            method[0]["payload"][facts.LOADING_CONSTRAINT_TYPE_OWNERS_KEY],
            ["java/lang/String"],
        )
        static_method = facts.BinaryFactStore._instruction_edges(
            ["method", 2, 184, "pkg/Owner", "start", "()V", False]
        )
        self.assertEqual(
            [row["edge_kind"] for row in static_method], ["method", "class_init"]
        )
        self.assertEqual(static_method[1]["payload"]["trigger_kind"], "invokestatic")

        for opcode, trigger in ((180, None), (178, "getstatic"), (179, "putstatic")):
            edges = facts.BinaryFactStore._instruction_edges(
                ["field", 3, opcode, "pkg/Owner", "VALUE", "Ljava/lang/String;"]
            )
            self.assertEqual(len(edges), 1 if trigger is None else 2)
            if trigger:
                self.assertEqual(edges[1]["payload"]["trigger_kind"], trigger)

        for opcode, use_kind, initializes in (
            (187, "new", True),
            (189, "anewarray", False),
            (192, "checkcast", False),
            (193, "instanceof", False),
            (197, "multianewarray", False),
            (999, "type_instruction", False),
        ):
            edges = facts.BinaryFactStore._instruction_edges(
                ["type", 4, opcode, "pkg/Type"]
            )
            self.assertEqual(edges[0]["payload"]["type_use_kind"], use_kind)
            self.assertEqual(len(edges), 2 if initializes else 1)

        multi = facts.BinaryFactStore._instruction_edges(
            ["multianewarray", 5, "[[Ljava/lang/String;", 2]
        )
        self.assertEqual(multi[0]["symbolic_owner"], "[[Ljava/lang/String;")
        self.assertEqual(multi[0]["payload"]["dimensions"], 2)
        for short in (
            ["method", 0], ["field", 0], ["type", 0],
            ["multianewarray", 0], ["invokedynamic", 0], ["ldc", 0],
        ):
            self.assertEqual(facts.BinaryFactStore._instruction_edges(short), [])

    def test_invokedynamic_and_ldc_nested_constant_matrix(self):
        bootstrap = {
            "kind": "handle", "tag": 6, "owner": "boot/Linker",
            "name": "link", "descriptor": "(Lboot/In;)Lboot/Out;",
        }
        nested_handle = {
            "kind": "handle", "tag": 6, "owner": "target/Owner",
            "name": "call", "descriptor": "(Larg/Input;)Larg/Output;",
        }
        arguments = [
            None,
            {"kind": "type", "descriptor": "Ljava/lang/String;"},
            {"kind": "method_type", "descriptor": "(Ljava/util/List;)Ljava/util/Map;"},
            [nested_handle],
            {"kind": "constant_dynamic", "descriptor": "Ldynamic/Value;", "arguments": []},
        ]
        dynamic = facts.BinaryFactStore._instruction_edges([
            "invokedynamic", 7, "apply", "(Lcall/In;)Lcall/Out;", bootstrap,
            arguments,
        ])
        kinds = {row["edge_kind"] for row in dynamic}
        self.assertIn("invokedynamic_bootstrap", kinds)
        self.assertIn("invokedynamic_handle_0", kinds)
        self.assertIn("type", kinds)

        without_bootstrap = facts.BinaryFactStore._instruction_edges([
            "invokedynamic", 8, "run", "()V", None, [],
        ])
        self.assertEqual(without_bootstrap[0]["symbolic_owner"], "")
        non_handle_bootstrap = facts.BinaryFactStore._instruction_edges([
            "invokedynamic", 9, "run", "()V", {"kind": "type"}, [],
        ])
        self.assertEqual(non_handle_bootstrap[0]["symbolic_name"], "")
        empty_named_handle = {
            "kind": "handle", "tag": 6, "owner": None,
            "name": None, "descriptor": "()V",
        }
        empty_named_dynamic = facts.BinaryFactStore._instruction_edges([
            "invokedynamic", 9, "run", "()V", {"kind": "type"},
            [empty_named_handle],
        ])
        self.assertTrue(empty_named_dynamic)
        with self.assertRaises(facts.BinaryFactStoreError):
            facts.BinaryFactStore._instruction_edges([
                "invokedynamic", 9, "run", "()V", {"kind": "type"},
                [{**empty_named_handle, "descriptor": None}],
            ])

        method_type = facts.BinaryFactStore._instruction_edges([
            "ldc", 10, {"kind": "method_type", "descriptor": "(Lx/A;)Ly/B;"}
        ])
        self.assertEqual({row["symbolic_owner"] for row in method_type}, {"x/A", "y/B"})
        class_literal = facts.BinaryFactStore._instruction_edges([
            "ldc", 11, {"kind": "type", "descriptor": "[Ljava/lang/String;"}
        ])
        self.assertEqual(class_literal[0]["symbolic_owner"], "[Ljava/lang/String;")
        self.assertEqual(
            facts.BinaryFactStore._instruction_edges([
                "ldc", 11, {"kind": "type", "descriptor": None}
            ])[0]["symbolic_owner"],
            "",
        )
        handle = facts.BinaryFactStore._instruction_edges([
            "ldc", 12, {**nested_handle, "tag": 1, "descriptor": "Ljava/lang/String;"}
        ])
        self.assertEqual(handle[0]["edge_kind"], "ldc_handle")

        constant_dynamic = {
            "kind": "constant_dynamic",
            "name": "VALUE",
            "descriptor": "Ldynamic/Value;",
            "bootstrap": bootstrap,
            "arguments": [nested_handle, {"kind": "type", "descriptor": "Larg/Input;"}],
        }
        constant_edges = facts.BinaryFactStore._instruction_edges(
            ["ldc", 13, constant_dynamic]
        )
        constant_kinds = {row["edge_kind"] for row in constant_edges}
        self.assertIn("ldc_constant_dynamic", constant_kinds)
        self.assertIn("ldc_constant_dynamic_bootstrap", constant_kinds)
        self.assertIn("ldc_bootstrap_handle_0", constant_kinds)
        empty_bootstrap_constant = {
            "kind": "constant_dynamic", "name": "EMPTY", "descriptor": "I",
            "bootstrap": {**empty_named_handle},
            "arguments": [empty_named_handle],
        }
        self.assertTrue(facts.BinaryFactStore._instruction_edges(
            ["ldc", 13, empty_bootstrap_constant]
        ))
        for bad in (
            {**empty_bootstrap_constant, "bootstrap": {**empty_named_handle, "descriptor": None}},
            {**empty_bootstrap_constant, "bootstrap": None,
             "arguments": [{**empty_named_handle, "descriptor": None}]},
        ):
            with self.assertRaises(facts.BinaryFactStoreError):
                facts.BinaryFactStore._instruction_edges(["ldc", 13, bad])

        for constant in (
            1,
            {},
            {"kind": "unknown"},
            {"kind": "constant_dynamic", "descriptor": "I", "bootstrap": None, "arguments": None},
            {"kind": "constant_dynamic", "descriptor": "I", "bootstrap": {"kind": "type"}, "arguments": []},
        ):
            with self.subTest(constant=constant):
                result = facts.BinaryFactStore._instruction_edges(["ldc", 14, constant])
                if isinstance(constant, dict) and constant.get("kind") == "constant_dynamic":
                    self.assertTrue(result)
                else:
                    self.assertEqual(result, [])

    def test_descriptor_owner_loading_constraint_and_handle_matrix(self):
        self.assertEqual(facts.BinaryFactStore._descriptor_owner(None), "")
        self.assertEqual(facts.BinaryFactStore._descriptor_owner("[[I"), "")
        self.assertEqual(facts.BinaryFactStore._descriptor_owner("[[Lx/Y;"), "x/Y")
        self.assertEqual(facts.BinaryFactStore._type_symbolic_owner(None), "")
        self.assertEqual(facts.BinaryFactStore._type_symbolic_owner("[I"), "[I")
        self.assertEqual(facts.BinaryFactStore._type_symbolic_owner("Lx/Y;"), "x/Y")
        self.assertEqual(facts.BinaryFactStore._type_symbolic_owner("x/Y"), "x/Y")
        self.assertEqual(facts.BinaryFactStore._type_symbolic_owner("Lx/Y"), "Lx/Y")
        self.assertEqual(facts.BinaryFactStore._type_symbolic_owner("x/Y;"), "x/Y;")

        method_edge = {"symbolic_descriptor": "(Lx/B;Lx/A;Lx/B;)Lx/C;", "payload": None}
        constrained = facts.BinaryFactStore._with_loading_constraint_type_owners(
            method_edge, member_kind="method"
        )
        self.assertEqual(
            constrained["payload"][facts.LOADING_CONSTRAINT_TYPE_OWNERS_KEY],
            ["x/A", "x/B", "x/C"],
        )
        primitive = {
            "symbolic_descriptor": "I",
            "payload": {facts.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: ["stale"]},
        }
        self.assertNotIn(
            facts.LOADING_CONSTRAINT_TYPE_OWNERS_KEY,
            facts.BinaryFactStore._with_loading_constraint_type_owners(
                primitive, member_kind="field"
            )["payload"],
        )
        with self.assertRaises(facts.BinaryFactStoreError):
            facts.BinaryFactStore._member_reference_descriptor_owners(
                {"symbolic_descriptor": "I"}, member_kind="unknown"
            )
        with self.assertRaises(facts.BinaryFactStoreError):
            facts.BinaryFactStore._member_reference_descriptor_owners(
                {}, member_kind="method"
            )

        field_handle = {"tag": 1, "descriptor": "Lx/Field;"}
        method_handle = {"tag": 9, "descriptor": "(Lx/In;)Lx/Out;"}
        edge = {"symbolic_descriptor": field_handle["descriptor"], "payload": {}}
        self.assertIn(
            facts.LOADING_CONSTRAINT_TYPE_OWNERS_KEY,
            facts.BinaryFactStore._method_handle_with_loading_constraint_types(
                edge, field_handle
            )["payload"],
        )
        method_edge = {"symbolic_descriptor": method_handle["descriptor"], "payload": {}}
        self.assertEqual(
            len(facts.BinaryFactStore._method_handle_type_edges(method_handle, 1, opcode=18)),
            2,
        )
        self.assertEqual(
            len(facts.BinaryFactStore._method_handle_type_edges(field_handle, 1, opcode=18)),
            1,
        )
        for invalid in (
            {"tag": "bad", "descriptor": "I"},
            {"tag": "bad", "descriptor": None},
            {"tag": 0, "descriptor": "I"},
            {"tag": 6, "descriptor": "invalid"},
            {"tag": None, "descriptor": None},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts.BinaryFactStore._method_handle_with_loading_constraint_types(
                        {"symbolic_descriptor": invalid["descriptor"], "payload": {}},
                        invalid,
                    )
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts.BinaryFactStore._method_handle_type_edges(invalid, 1, opcode=18)

    def test_bootstrap_argument_deduplication_and_handle_collection_matrix(self):
        value = [
            "scalar",
            ({"kind": "type", "descriptor": "Lx/A;"},),
            {"kind": "method_type", "descriptor": "(Lx/A;)Lx/B;"},
            {
                "kind": "constant_dynamic", "descriptor": "Lx/C;",
                "arguments": [
                    {"kind": "type", "descriptor": "Lx/A;"},
                    {"kind": None},
                ],
            },
            {"kind": "type", "descriptor": ""},
        ]
        edges = facts.BinaryFactStore._bootstrap_argument_type_edges(value, 3)
        keys = {(row["symbolic_owner"], row["payload"]["type_use_kind"]) for row in edges}
        self.assertEqual(len(keys), len(edges))
        self.assertIn(("x/A", "bootstrap_class_constant"), keys)

        non_type = {"edge_kind": "method", "payload": None}
        type_one = {"edge_kind": "type", "symbolic_owner": None, "payload": None}
        type_two = {"edge_kind": "type", "symbolic_owner": None, "payload": {}}
        deduplicated = facts.BinaryFactStore._deduplicate_type_edges(
            [non_type, type_one, type_two]
        )
        self.assertEqual(deduplicated, [non_type, type_one])

        found = []
        handle = {"kind": "handle", "tag": 6}
        facts.BinaryFactStore._collect_handles(
            {"outer": [handle, {"nested": handle}], "tuple": (handle,)}, found
        )
        # Lists and dict values are traversed; tuples are opaque in this helper.
        self.assertEqual(found, [handle, handle])
        facts.BinaryFactStore._collect_handles("scalar", found)
        with self.assertRaises(facts.BinaryFactStoreError):
            facts.BinaryFactStore._bootstrap_argument_type_edges(
                {"kind": "constant_dynamic", "descriptor": None}, 3
            )

    def test_descriptor_parser_remaining_shape_boundaries(self):
        valid = ("()V", "(I)V", "()Ljava/lang/String;", "([I)[Ljava/lang/String;")
        for descriptor in valid:
            with self.subTest(valid=descriptor):
                facts.BinaryFactStore._method_descriptor_reference_owners(descriptor)
        invalid = (
            "(", "(I", "(II", "(I)", "([)V", "([[",
            "(" + "[" * 256 + "I)V",
        )
        for descriptor in invalid:
            with self.subTest(invalid=descriptor):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts.BinaryFactStore._method_descriptor_reference_owners(descriptor)

        for descriptor in (
            "[" * 256 + "I", "II", "L;", "L/bad;", "Lbad/;",
            "Lbad.Name;", "Lbad[Name;",
        ):
            with self.subTest(field=descriptor):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts.BinaryFactStore._field_descriptor_reference_owner(descriptor)

    def test_runtime_trigger_summary_validation_and_fact_components_matrix(self):
        valid = {
            "has_runtime_annotations": False,
            "hierarchy_types": frozenset({"java/lang/Object"}),
            "has_main_method": True,
        }
        self.assertEqual(
            facts.BinaryFactStore._validated_runtime_trigger_summary(valid), valid
        )
        invalid = (
            None,
            {},
            {**valid, "extra": True},
            {**valid, "has_runtime_annotations": 0},
            {**valid, "has_main_method": 1},
            {**valid, "hierarchy_types": set()},
            {**valid, "hierarchy_types": frozenset({""})},
            {**valid, "hierarchy_types": frozenset({1})},
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts.BinaryFactStore._validated_runtime_trigger_summary(value)

        main = {
            "contract": {
                "name": "main", "descriptor": "([Ljava/lang/String;)V",
                "annotations": ["method-annotation"],
            }
        }
        fact = {
            "annotations": [],
            "fields": [None, {"annotations": []}, {"annotations": ["field"]}],
            "methods": [
                None, {"contract": None}, {"contract": {}},
                {"contract": {"name": "main", "descriptor": None}}, main,
            ],
            "super_name": "java/lang/Object",
            "interfaces": [None, "java/io/Serializable"],
        }
        annotations, hierarchy, has_main = facts.BinaryFactStore._runtime_trigger_fact_components(
            fact, include_main_method=True
        )
        self.assertTrue(annotations)
        self.assertEqual(hierarchy, ("java/lang/Object", "java/io/Serializable"))
        self.assertTrue(has_main)
        self.assertFalse(
            facts.BinaryFactStore._runtime_trigger_fact_components(
                fact, include_main_method=False
            )[2]
        )
        self.assertEqual(
            facts.BinaryFactStore._runtime_trigger_fact_components(
                {"annotations": ["class"], "methods": None, "interfaces": None},
                include_main_method=True,
            ),
            (True, (), False),
        )
        method_annotation_only = {
            "annotations": [], "fields": [],
            "methods": [
                None, {"contract": None}, {"contract": {}},
                {"contract": {"annotations": []}},
                {"contract": {"annotations": ["runtime"]}},
            ],
        }
        self.assertTrue(
            facts.BinaryFactStore._runtime_trigger_fact_components(
                method_annotation_only, include_main_method=True
            )[0]
        )
        self.assertFalse(
            facts.BinaryFactStore._runtime_trigger_fact_components(
                {"methods": [
                    {"contract": {"name": "main", "descriptor": None}},
                    {"contract": {"name": None, "descriptor": "([Ljava/lang/String;)V"}},
                ]},
                include_main_method=True,
            )[2]
        )

    def test_runtime_summary_scan_empty_and_populated_rows(self):
        class QueryResult:
            def __init__(self, rows=(), one=None):
                self.rows = list(rows)
                self.one = one

            def __iter__(self):
                return iter(self.rows)

            def fetchone(self):
                return self.one

        class QueryConnection:
            def __init__(self, rows, main):
                self.rows = rows
                self.main = main

            def execute(self, query):
                if "FROM classes" in query:
                    return QueryResult(self.rows)
                if "FROM members" in query:
                    return QueryResult(one=(1,) if self.main else None)
                raise AssertionError(query)

        class FakeStore:
            def __init__(self, rows, main):
                self.connection = QueryConnection(rows, main)
                self._runtime_trigger_summary_cache = None
                self._runtime_trigger_summary_data_version = None

            def _runtime_trigger_data_version(self):
                return 3

            def _validated_runtime_trigger_summary(self, value):
                return facts.BinaryFactStore._validated_runtime_trigger_summary(value)

            def _runtime_trigger_summary_copy(self, value):
                return facts.BinaryFactStore._runtime_trigger_summary_copy(value)

        empty = facts.BinaryFactStore.runtime_trigger_summary(
            FakeStore([(0, None, "[]")], False)
        )
        self.assertEqual(empty, facts.BinaryFactStore._empty_runtime_trigger_summary())
        populated = facts.BinaryFactStore.runtime_trigger_summary(FakeStore([
            (1, "base/Type", '["iface/One","",null]'),
            (0, None, "[]"),
        ], True))
        self.assertTrue(populated["has_runtime_annotations"])
        self.assertTrue(populated["has_main_method"])
        self.assertEqual(
            populated["hierarchy_types"], frozenset({"base/Type", "iface/One"})
        )

    def test_runtime_data_version_shape_matrix(self):
        for row in (None, (True,), (-1,), ("1",)):
            fake = SimpleNamespace(connection=VersionConnection(row))
            with self.subTest(row=row):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts.BinaryFactStore._runtime_trigger_data_version(fake)
        fake = SimpleNamespace(connection=VersionConnection((7,)))
        self.assertEqual(facts.BinaryFactStore._runtime_trigger_data_version(fake), 7)

    def test_schema_query_and_payload_option_failure_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, setup in (
                ("no-metadata.sqlite", "CREATE TABLE arbitrary(value TEXT)"),
                ("empty-metadata.sqlite", "CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)"),
                ("broken-metadata.sqlite", "CREATE TABLE metadata(wrong TEXT)"),
            ):
                path = root / name
                connection = sqlite3.connect(path)
                connection.execute(setup)
                connection.commit()
                connection.close()
                with self.subTest(name=name), self.assertRaises(facts.BinaryFactStoreError):
                    facts.BinaryFactStore(path)

        with facts.BinaryFactStore() as store:
            with self.assertRaises(facts.BinaryFactStoreError):
                store.rows("unknown")
            with self.assertRaises(facts.BinaryFactStoreError):
                store.rows("reconciliation_records", where="record_kind=1")
            for table in ("members", "metadata"):
                for bytes_flag, facts_flag in ((False, True), (True, False), (False, False)):
                    with self.subTest(table=table, bytes=bytes_flag, facts=facts_flag):
                        with self.assertRaises(facts.BinaryFactStoreError):
                            store.rows(
                                table, include_class_bytes=bytes_flag,
                                include_class_facts=facts_flag,
                            )
            self.assertEqual(store.rows("classes", include_class_bytes=False), [])
            self.assertEqual(store.rows("classes", include_class_facts=False), [])
            self.assertEqual(store.rows(
                "classes", include_class_bytes=False, include_class_facts=False
            ), [])
            self.assertEqual(store.rows("metadata", where="key=?", parameters=("missing",)), [])
            with self.assertRaises(facts.BinaryFactStoreError):
                store.class_bytes("missing")

    def test_reconciliation_empty_invalid_context_and_corruption_matrix(self):
        with facts.BinaryFactStore() as store:
            self.assertEqual(store.add_reconciliation_records([]), [])
            self.assertEqual(store.add_reconciliation_payloads(
                analysis_context_identity="context", record_kind="provider_binding",
                records=[], collect_identities=False,
            ), [])
            for kind in ("", "unknown"):
                with self.subTest(kind=kind):
                    with self.assertRaises(facts.BinaryFactStoreError):
                        store.add_reconciliation_payloads(
                            analysis_context_identity="context", record_kind=kind,
                            records=[],
                        )
                    with self.assertRaises(facts.BinaryFactStoreError):
                        list(store.reconciliation_payloads(kind))

            payloads = [
                ("resolved", "one", {"value": 1}),
                ("missing", "two", [("value", 2)]),
            ]
            identities = store.add_reconciliation_payloads(
                analysis_context_identity="context", record_kind="provider_binding",
                records=payloads,
            )
            self.assertEqual(len(identities), 2)
            self.assertEqual(
                list(store.reconciliation_payloads("provider_binding")),
                [{"value": 1}, {"value": 2}],
            )
            with self.assertRaises(facts.BinaryFactStoreError):
                store.add_reconciliation_payloads(
                    analysis_context_identity="different", record_kind="provider_binding",
                    records=[],
                )

            store.connection.execute(
                "UPDATE reconciliation_records SET record_count=record_count+1"
            )
            store.connection.commit()
            with self.assertRaises(facts.BinaryFactStoreError):
                store.rows("reconciliation_records")
            with self.assertRaises(facts.BinaryFactStoreError):
                list(store.reconciliation_payloads("provider_binding"))

    def test_reconciliation_chunk_decoders_fail_closed_for_every_shape_boundary(self):
        def compressed(value):
            return zlib.compress(
                json.dumps(value, separators=(",", ":")).encode("utf-8")
            )

        columnar = {
            "format": facts._RECONCILIATION_PAYLOAD_FORMAT,
            "records": [[0, 1]],
            "shapes": [["value"]],
        }
        valid_payloads, legacy = facts._decode_reconciliation_payload_chunk(
            compressed(columnar), 1, "valid-columnar"
        )
        self.assertEqual(valid_payloads, [{"value": 1}])
        self.assertIsNone(legacy)

        invalid_payloads = (
            {**columnar, "extra": True},
            {**columnar, "records": {}},
            {**columnar, "shapes": {}},
            {**columnar, "shapes": ["value"]},
            {**columnar, "shapes": [[1]]},
            {**columnar, "shapes": [["z", "a"]], "records": [[0, 1, 2]]},
            {**columnar, "shapes": [["a"], ["a"]]},
            {**columnar, "records": [{}]},
            {**columnar, "records": [[]]},
            {**columnar, "records": [[True, 1]]},
            {**columnar, "records": [[-1, 1]]},
            {**columnar, "records": [[1, 1]]},
            {**columnar, "records": [[0]]},
            {
                "format": facts._RECONCILIATION_LEGACY_PAYLOAD_FORMAT,
                "records": [],
                "extra": True,
            },
            {
                "format": facts._RECONCILIATION_LEGACY_PAYLOAD_FORMAT,
                "records": {},
            },
            {"format": "unknown", "records": []},
            7,
            ["not-an-envelope"],
            [{"record_identity": "id", "status": "ok", "subject_identity": "s"}],
        )
        for ordinal, value in enumerate(invalid_payloads):
            with self.subTest(payload_case=ordinal):
                with self.assertRaises(facts.BinaryFactStoreError) as caught:
                    facts._decode_reconciliation_payload_chunk(
                        compressed(value), 1, f"bad-payload-{ordinal}"
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "FACT_STORE_RECONCILIATION_CHUNK_INVALID",
                )

        for ordinal, (value, count) in enumerate((
            ({**columnar, "records": []}, 1),
            ({
                "format": facts._RECONCILIATION_LEGACY_PAYLOAD_FORMAT,
                "records": [1],
            }, 1),
        )):
            with self.subTest(payload_terminal_case=ordinal):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts._decode_reconciliation_payload_chunk(
                        compressed(value), count, f"bad-terminal-{ordinal}"
                    )
        with self.assertRaises(facts.BinaryFactStoreError):
            facts._decode_reconciliation_payload_chunk(
                b"not-zlib", 0, "bad-zlib"
            )

        metadata = {
            "format": facts._RECONCILIATION_METADATA_FORMAT,
            "records": [["resolved", "subject"]],
        }
        self.assertEqual(
            facts._decode_reconciliation_metadata_chunk(
                compressed(metadata), 1, "valid-metadata", "provider_binding",
                [{"value": 1}],
            ),
            [("resolved", "subject")],
        )
        invalid_metadata = (
            [],
            {**metadata, "extra": True},
            {**metadata, "records": {}},
            {**metadata, "records": []},
            {**metadata, "records": ["bad"]},
            {**metadata, "records": [["only-one"]]},
            {**metadata, "records": [["resolved", 1]]},
            {
                "format": facts._RECONCILIATION_DERIVED_METADATA_FORMAT,
                "status_field": "wrong",
                "subject_field": "wrong",
            },
        )
        for ordinal, value in enumerate(invalid_metadata):
            with self.subTest(metadata_case=ordinal):
                with self.assertRaises(facts.BinaryFactStoreError) as caught:
                    facts._decode_reconciliation_metadata_chunk(
                        compressed(value), 1, f"bad-metadata-{ordinal}",
                        "provider_binding", [{"value": 1}],
                    )
                self.assertEqual(
                    caught.exception.reason_code,
                    "FACT_STORE_RECONCILIATION_METADATA_INVALID",
                )

        derived = {
            "format": facts._RECONCILIATION_DERIVED_METADATA_FORMAT,
            "status_field": "class_provider_status",
            "subject_field": "provider_binding_identity",
        }
        self.assertEqual(
            facts._decode_reconciliation_metadata_chunk(
                compressed(derived), 1, "derived", "provider_binding", [{
                    "class_provider_status": "resolved",
                    "provider_binding_identity": "binding",
                }],
            ),
            [("resolved", "binding")],
        )
        for ordinal, (payloads, count) in enumerate((
            ([{"provider_binding_identity": "binding"}], 1),
            ([{
                "class_provider_status": 1,
                "provider_binding_identity": "binding",
            }], 1),
            ([{
                "class_provider_status": "resolved",
                "provider_binding_identity": 1,
            }], 1),
            ([{
                "class_provider_status": "resolved",
                "provider_binding_identity": "binding",
            }], 2),
        )):
            with self.subTest(derived_case=ordinal):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts._decode_reconciliation_metadata_chunk(
                        compressed(derived), count, f"bad-derived-{ordinal}",
                        "provider_binding", payloads,
                    )

    def test_runtime_reference_projection_and_reconciliation_small_api_matrix(self):
        self.assertEqual(facts.BinaryFactStore._runtime_provider_owner(""), "")
        self.assertEqual(
            facts.BinaryFactStore._runtime_provider_owner("pkg/Owner"),
            "pkg/Owner",
        )
        self.assertEqual(
            facts.BinaryFactStore._runtime_provider_owner("[[Lpkg/Owner;"),
            "pkg/Owner",
        )
        self.assertEqual(
            facts.BinaryFactStore._runtime_provider_owner("[[I"), ""
        )
        self.assertEqual(
            facts.BinaryFactStore._runtime_provider_owner("[[Lpkg/Open"), ""
        )
        self.assertEqual(facts.BinaryFactStore._descriptor_owner("Lpkg/Open"), "")

        self.assertEqual(
            facts.BinaryFactStore._runtime_class_references({}), set()
        )
        self.assertEqual(
            facts.BinaryFactStore._runtime_class_references({
                "symbolic_owner": "pkg/Owner", "payload": None,
            }),
            {("symbolic_owner", "pkg/Owner")},
        )
        expected = {
            ("symbolic_owner", "pkg/Owner"),
            ("loading_constraint_owner", "pkg/A"),
            ("loading_constraint_owner", "pkg/B"),
        }
        self.assertEqual(
            facts.BinaryFactStore._runtime_class_references({
                "symbolic_owner": "[Lpkg/Owner;",
                "payload": {
                    facts.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: ["pkg/A", "pkg/B"]
                },
            }),
            expected,
        )
        for ordinal, owners in enumerate((
            "pkg/A", [], [""], [1], ["pkg/B", "pkg/A"], ["pkg/A", "pkg/A"],
        )):
            with self.subTest(reference_case=ordinal):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts.BinaryFactStore._runtime_class_references({
                        "symbolic_owner": "[[I",
                        "symbolic_descriptor": "()V",
                        "payload": {
                            facts.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: owners
                        },
                    })
        with self.assertRaises(facts.BinaryFactStoreError):
            facts.BinaryFactStore._runtime_class_references({
                "payload": {facts.LOADING_CONSTRAINT_TYPE_OWNERS_KEY: []},
            })

        class RecordingConnection:
            def __init__(self):
                self.calls = []

            def execute(self, query, values):
                self.calls.append((query, values))

        fake_store = SimpleNamespace(
            connection=RecordingConnection(),
            _member_values=facts.BinaryFactStore._member_values,
        )
        member_identity = facts.BinaryFactStore._insert_member(
            fake_store, "variant", "artifact", "pkg/Owner", "method",
            {"name": "run", "descriptor": "()V", "access": 1}, "digest",
        )
        self.assertEqual(len(member_identity), 64)
        self.assertEqual(len(fake_store.connection.calls), 1)

        with facts.BinaryFactStore() as store:
            record_identity = store.add_reconciliation_record(
                analysis_context_identity="context",
                record_kind="provider_binding",
                status="resolved",
                subject_identity="binding",
                payload={"value": 1},
            )
            self.assertEqual(len(record_identity), 64)
            self.assertEqual(store.reconciliation_payload_count("provider_binding"), 1)
            for kind in (None, "", "unknown"):
                with self.subTest(count_kind=kind):
                    with self.assertRaises(facts.BinaryFactStoreError):
                        store.reconciliation_payload_count(kind)

        with facts.BinaryFactStore() as store:
            store.connection.execute("BEGIN")
            self.assertEqual(store.add_reconciliation_records([]), [])

    def test_reconciliation_specialized_writer_shape_cache_and_validation_matrix(self):
        with facts.BinaryFactStore() as store:
            records = [
                ("s0", "a" * 64, {"z": 1, "a": 2}),
                ("s0", "b" * 64, {"z": 3, "a": 4}),
                ("s1", "short", {"a": 5, "z": 6}),
                ("s1", "short", {"other": 7}),
            ]
            identities = store.add_reconciliation_payloads(
                analysis_context_identity="context",
                record_kind="provider_binding",
                records=records,
            )
            self.assertEqual(len(identities), len(records))

            cache_records = [
                (f"status-{index}", "é" * 64 if index == 0 else (
                    "_" * 64 if index == 1 else f"subject-{index}"
                ), {"index": index})
                for index in range(66)
            ]
            self.assertEqual(len(store.add_reconciliation_payloads(
                analysis_context_identity="context",
                record_kind="provider_binding",
                records=cache_records,
                collect_identities=False,
            )), 0)

            with self.assertRaises(facts.BinaryFactStoreError) as caught:
                store.add_reconciliation_payloads(
                    analysis_context_identity="context",
                    record_kind="provider_binding",
                    records=[],
                    derive_metadata_from_payload=1,
                )
            self.assertEqual(
                caught.exception.reason_code,
                "FACT_STORE_RECONCILIATION_METADATA_MODE_INVALID",
            )
            with self.assertRaises(facts.BinaryFactStoreError):
                store.add_reconciliation_payloads(
                    analysis_context_identity="context",
                    record_kind="provider_binding",
                    records=[("s", "subject", {1: "non-string-key"})],
                )

        derived_base = {
            "class_provider_status": "resolved",
            "provider_binding_identity": "binding",
        }
        with facts.BinaryFactStore() as store:
            self.assertEqual(len(store.add_reconciliation_payloads(
                analysis_context_identity="derived",
                record_kind="provider_binding",
                records=[
                    ("resolved", "binding", derived_base),
                    ("resolved", "binding-2", {
                        **derived_base,
                        "provider_binding_identity": "binding-2",
                    }),
                ],
                derive_metadata_from_payload=True,
            )), 2)
            for ordinal, row in enumerate((
                ("wrong", "binding", derived_base),
                ("resolved", "wrong", derived_base),
            )):
                with self.subTest(derived_write_case=ordinal):
                    with self.assertRaises(facts.BinaryFactStoreError):
                        store.add_reconciliation_payloads(
                            analysis_context_identity="derived",
                            record_kind="provider_binding",
                            records=[row],
                            derive_metadata_from_payload=True,
                        )

    def test_class_fact_normalization_rejects_ambiguous_or_corrupt_identity(self):
        identity = "a" * 64
        field = f'"artifact_instance_identity":"{identity}"'
        for document in ("{}", "{" + field + "," + field + "}"):
            with self.subTest(document=document):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts._encode_stored_class_fact(document, identity)

        for raw in (b"{}", b"{\xff}"):
            compressed = zlib.compress(raw)
            with self.subTest(raw=raw):
                with self.assertRaises(facts.BinaryFactStoreError):
                    facts._decode_stored_class_fact(
                        compressed, identity,
                        __import__("hashlib").sha256(compressed).hexdigest(),
                    )

    def test_reconciliation_rows_without_context_rebuild_v11_identity(self):
        with facts.BinaryFactStore() as store:
            store.add_reconciliation_payloads(
                analysis_context_identity="context",
                record_kind="provider_binding",
                records=[("resolved", "subject", {"value": 1})],
            )
            store.connection.execute(
                "DELETE FROM metadata WHERE key=?",
                ("reconciliation_analysis_context_identity",),
            )
            store.connection.commit()
            rows = store.rows("reconciliation_records")

        self.assertEqual(rows[0]["analysis_context_identity"], "")

    def test_content_identity_rejects_table_without_primary_key(self):
        class NoPrimaryKeyConnection:
            def execute(self, query):
                if query.startswith("PRAGMA table_info("):
                    return [(0, "value", "TEXT", 0, None, 0)]
                raise AssertionError(query)

        fake = SimpleNamespace(connection=NoPrimaryKeyConnection())
        with self.assertRaises(facts.BinaryFactStoreError) as caught:
            facts.BinaryFactStore.content_identity(fake)
        self.assertEqual(
            caught.exception.reason_code,
            "FACT_STORE_CONTENT_IDENTITY_ORDER_MISSING",
        )

    def test_reconciliation_normalized_context_kind_and_conflict_matrix(self):
        with facts.BinaryFactStore() as store:
            with self.assertRaises(facts.BinaryFactStoreError):
                store.add_reconciliation_records([{
                    "analysis_context_identity": "context",
                    "record_kind": "unknown",
                    "status": "x", "subject_identity": "s", "payload": {},
                }])
            records = [
                {
                    "analysis_context_identity": "context",
                    "record_kind": "provider_binding",
                    "status": "resolved", "subject_identity": "one", "payload": {},
                },
                {
                    "analysis_context_identity": "context",
                    "record_kind": "member_resolution",
                    "status": "resolved", "subject_identity": "two", "payload": {},
                },
            ]
            self.assertEqual(
                store.add_reconciliation_records(records, collect_identities=False), []
            )
            same_context = {
                **records[0], "subject_identity": "same-context-second-call"
            }
            self.assertEqual(len(store.add_reconciliation_records([same_context])), 1)
            with self.assertRaises(facts.BinaryFactStoreError):
                store.add_reconciliation_records([{
                    **records[0], "analysis_context_identity": "different",
                }])

        with facts.BinaryFactStore() as store:
            mixed = [
                {
                    "analysis_context_identity": "one", "record_kind": "provider_binding",
                    "status": "x", "subject_identity": "x", "payload": {},
                },
                {
                    "analysis_context_identity": "two", "record_kind": "provider_binding",
                    "status": "y", "subject_identity": "y", "payload": {},
                },
            ]
            with self.assertRaises(facts.BinaryFactStoreError):
                store.add_reconciliation_records(mixed)

    def test_snapshot_identity_failures_and_overlay_integrity_wrapping(self):
        with facts.BinaryFactStore() as store:
            instance = SimpleNamespace(identity="instance", content_sha256="content")
            wrong_identity = SimpleNamespace(
                artifact_instance_identity="other", artifact_content_sha256="content"
            )
            with self.assertRaises(facts.BinaryFactStoreError) as raised:
                store.add_artifact_snapshot(instance, wrong_identity)
            self.assertEqual(raised.exception.reason_code, "FACT_STORE_ARTIFACT_IDENTITY_MISMATCH")
            wrong_content = SimpleNamespace(
                artifact_instance_identity="instance", artifact_content_sha256="other"
            )
            with self.assertRaises(facts.BinaryFactStoreError) as raised:
                store.add_artifact_snapshot(instance, wrong_content)
            self.assertEqual(raised.exception.reason_code, "FACT_STORE_ARTIFACT_CONTENT_MISMATCH")

            with self.assertRaises(facts.BinaryFactStoreError):
                store.add_source_overlay(
                    overlay_identity="overlay", analysis_context_identity="context",
                    binary_member_identity="missing", mapping_status="mapped",
                    source_location={}, conflict={},
                )
            for consumer in (None, "missing-consumer"):
                with self.subTest(consumer=consumer):
                    with self.assertRaises(facts.BinaryFactStoreError):
                        store.add_inline_overlay({
                            "inline_overlay_identity": "inline" + str(consumer),
                            "analysis_context_identity": "context",
                            "changed_field_member_identity": "missing",
                            "consumer_member_identity": consumer,
                            "consumption_state": "unbound",
                            "binding_certainty": "none",
                            "coverage_status": "partial",
                        })

    def test_minimal_snapshot_ingestion_unbound_and_parsed_failed_records(self):
        instance = self._instance()
        with facts.BinaryFactStore() as store:
            self.assertEqual(
                store.add_artifact_snapshot(instance, self._snapshot()),
                {"entries": 0, "classes": 0, "members": 0, "edges": 0, "resources": 0},
            )

        with facts.BinaryFactStore() as store:
            store._runtime_trigger_summary_cache = None
            store._runtime_trigger_summary_data_version = None
            store.add_artifact_snapshot(instance, self._snapshot())

        with facts.BinaryFactStore() as store:
            store._runtime_trigger_summary_cache = facts.BinaryFactStore._empty_runtime_trigger_summary()
            store._runtime_trigger_summary_data_version = -1
            store.add_artifact_snapshot(instance, self._snapshot())

        class_entry = self._entry("pkg/Example.class", 0)
        resource_ignored = self._entry("config/ignored.bin", 1, kind="resource")
        resource_effective = self._entry(
            "config/effective.bin", 2, kind="resource", effective=True
        )
        label = "pkg/Example.class#occurrence=0"
        parsed = {
            "frame_type": "class_fact",
            "artifact_instance_identity": "instance",
            "class_entry": label,
            "class_name": None,
            "class_bytes_sha256": None,
            "class_contract_digest": None,
            "class_major": None,
            "class_access": None,
            "failure_kind": None,
            "super_name": "java/lang/Object",
            "interfaces": None,
            "nest_host": None,
            "nest_members": None,
            "annotations": ["annotation"],
            "fields": [{}],
            "methods": [
                {"contract": None, "implementation_digest": None, "instructions": None},
                {
                    "contract": {
                        "name": "main", "descriptor": "([Ljava/lang/String;)V",
                        "access": None,
                    },
                    "implementation_digest": "main-digest",
                    "instructions": [["unknown", 0]],
                },
            ],
        }
        snapshot = self._snapshot(
            [class_entry, resource_ignored, resource_effective],
            [parsed], [(label, b"class-bytes")],
        )
        with facts.BinaryFactStore() as store:
            counts = store.add_artifact_snapshot(instance, snapshot)
            self.assertEqual(counts, {
                "entries": 3, "classes": 1, "members": 3,
                "edges": 0, "resources": 1,
            })
            class_row = store.rows("classes")[0]
            self.assertEqual(class_row["class_name"], "pkg/Example")
            self.assertEqual(class_row["parse_status"], "parsed")
            self.assertTrue(store.runtime_trigger_summary()["has_main_method"])

        second_entry = self._entry("pkg/Second.class", 3)
        second_label = "pkg/Second.class#occurrence=3"
        second_record = {
            "frame_type": "class_fact", "class_entry": second_label,
            "artifact_instance_identity": "instance",
            "class_name": "pkg/Second", "class_bytes_sha256": "second",
            "annotations": [], "fields": None, "methods": None,
            "super_name": None, "interfaces": [],
            "nest_members": ["pkg/Second$Nested"],
        }
        combined = self._snapshot(
            [class_entry, second_entry], [parsed, second_record],
            [(label, b"class-bytes"), (second_label, b"second")],
        )
        with facts.BinaryFactStore() as store:
            combined_counts = store.add_artifact_snapshot(instance, combined)
            self.assertEqual(combined_counts["classes"], 2)

        failed_entry = self._entry("pkg/Failed.class", 0)
        failed_label = "pkg/Failed.class#occurrence=0"
        failed = {
            "frame_type": "class_error", "class_entry": failed_label,
            "artifact_instance_identity": "instance",
            "class_name": "pkg/Failed", "failure_kind": "parse_error",
            "interfaces": [], "nest_members": [],
        }
        with facts.BinaryFactStore() as store:
            counts = store.add_artifact_snapshot(
                instance,
                self._snapshot([failed_entry], [failed], [(failed_label, b"bad")]),
            )
            self.assertEqual(counts["classes"], 1)
            self.assertEqual(counts["members"], 0)
            self.assertEqual(store.rows("classes")[0]["parse_status"], "failed")

        with facts.BinaryFactStore() as store:
            with self.assertRaises(facts.BinaryFactStoreError):
                store.add_artifact_snapshot(
                    instance, self._snapshot([], [{"class_entry": None}], [])
                )
        with facts.BinaryFactStore() as store:
            with self.assertRaises(facts.BinaryFactStoreError):
                store.add_artifact_snapshot(
                    instance, self._snapshot([class_entry], [parsed], [])
                )

        with facts.BinaryFactStore(
            defer_secondary_indexes=True, bulk_load_transaction=True
        ) as store:
            with self.assertRaises(facts.BinaryFactStoreError):
                store.add_artifact_snapshot(
                    instance, self._snapshot([], [{"class_entry": None}], [])
                )

        with facts.BinaryFactStore() as store, patch.object(
            store, "_runtime_trigger_data_version", side_effect=[0, 1]
        ):
            store._runtime_trigger_summary_cache = facts.BinaryFactStore._empty_runtime_trigger_summary()
            store._runtime_trigger_summary_data_version = 0
            store.add_artifact_snapshot(instance, self._snapshot())

    def test_bulk_index_commit_and_reconciliation_rows_without_context(self):
        with facts.BinaryFactStore(
            defer_secondary_indexes=True, bulk_load_transaction=True
        ) as store:
            self.assertTrue(store.connection.in_transaction)
            store.ensure_secondary_indexes()
            self.assertFalse(store._bulk_load_transaction)

        with facts.BinaryFactStore() as store:
            envelope = [{
                "record_identity": "identity", "status": "resolved",
                "subject_identity": "subject", "payload": {},
            }]
            store.connection.execute(
                "INSERT INTO reconciliation_records VALUES(?,?,?,?,?)",
                (
                    sqlite3.Binary(b"x" * 32),
                    facts.RECONCILIATION_KIND_CODES["provider_binding"],
                    1,
                    sqlite3.Binary(zlib.compress(
                        json.dumps(envelope).encode("utf-8"), level=1
                    )),
                    sqlite3.Binary(zlib.compress(b"{}", level=1)),
                ),
            )
            store.connection.commit()
            rows = store.rows("reconciliation_records")
            self.assertEqual(rows[0]["analysis_context_identity"], "")

    def test_backup_adoption_self_unstable_versions_and_sqlite_failure(self):
        with facts.BinaryFactStore() as source, facts.BinaryFactStore() as destination:
            with self.assertRaises(facts.BinaryFactStoreError):
                source.adopt_runtime_trigger_summary_from_exact_backup(source)

            with patch.object(
                source, "_runtime_trigger_data_version", side_effect=[1, 2]
            ), patch.object(
                destination, "_runtime_trigger_data_version", return_value=1
            ), patch.object(
                source, "runtime_trigger_summary",
                return_value=facts.BinaryFactStore._empty_runtime_trigger_summary(),
            ):
                with self.assertRaises(facts.BinaryFactStoreError) as raised:
                    destination.adopt_runtime_trigger_summary_from_exact_backup(source)
            self.assertEqual(
                raised.exception.reason_code,
                "FACT_STORE_RUNTIME_TRIGGER_BACKUP_UNSTABLE",
            )

            with patch.object(
                source, "_runtime_trigger_data_version", return_value=1
            ), patch.object(
                destination, "_runtime_trigger_data_version", side_effect=[1, 2]
            ), patch.object(
                source, "runtime_trigger_summary",
                return_value=facts.BinaryFactStore._empty_runtime_trigger_summary(),
            ):
                with self.assertRaises(facts.BinaryFactStoreError):
                    destination.adopt_runtime_trigger_summary_from_exact_backup(source)

            with patch.object(source, "counts", side_effect=sqlite3.Error("bad db")):
                with self.assertRaises(facts.BinaryFactStoreError) as raised:
                    destination.adopt_runtime_trigger_summary_from_exact_backup(source)
            self.assertEqual(
                raised.exception.reason_code,
                "FACT_STORE_RUNTIME_TRIGGER_BACKUP_INVALID",
            )


if __name__ == "__main__":
    unittest.main()
