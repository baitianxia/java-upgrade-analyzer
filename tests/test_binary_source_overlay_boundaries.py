import json
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT_DIR / "scripts"))

import binary_source_overlay as overlay  # noqa: E402


class Method(SimpleNamespace):
    def get_body_text(self):
        return getattr(self, "body", "")


class Store:
    def __init__(self, **tables):
        self.tables = {key: list(value) for key, value in tables.items()}
        self.source_rows = []
        self.inline_rows = []
        self.physical_consumers = set()

    def rows(self, table, where=None, parameters=()):
        rows = list(self.tables.get(table, ()))
        if table == "classes" and parameters:
            rows = [
                row for row in rows
                if row.get("class_variant_identity") == parameters[0]
            ]
        if table == "direct_edges" and parameters:
            return rows if parameters[0] in self.physical_consumers else []
        return rows

    def add_source_overlay(self, **row):
        self.source_rows.append(row)

    def add_inline_overlay(self, row):
        self.inline_rows.append(dict(row))


def method(**values):
    defaults = {
        "symbol_id": "symbol",
        "class_fqcn": "demo.Sample",
        "class_name": "Sample",
        "method_name": "run",
        "param_types": {},
        "param_declared_types": {},
        "return_type": "void",
        "return_declared_type": "",
        "known_classes_by_simple": {},
        "imports": {},
        "static_imports": {},
        "package_name": "demo",
        "language": "java",
        "body": "",
        "file": "",
        "source_root": "",
        "line": 0,
        "end_line": 0,
        "owner_type": "",
        "owner_coord": "",
        "module": "",
    }
    defaults.update(values)
    return Method(**defaults)


def member(identity, owner="demo/Sample", name="run", descriptor="()V", **values):
    row = {
        "member_identity": identity,
        "class_variant_identity": values.pop("class_variant_identity", "variant"),
        "artifact_instance_identity": values.pop("artifact_instance_identity", "artifact"),
        "class_name": owner,
        "member_kind": values.pop("member_kind", "method"),
        "member_name": name,
        "descriptor": descriptor,
        "access_flags": values.pop("access_flags", 0),
        "implementation_digest": values.pop("implementation_digest", identity + "-digest"),
    }
    row.update(values)
    return row


def field_diff(*, old=1, new=2, access=0x18, kind="field", entries=True):
    delta = {
        "member_scope": {
            "member_kind": kind,
            "member_name": "VALUE",
            "descriptor": "I",
        },
        "base_contract": {"access": access, "constant": old},
        "current_contract": {"access": access, "constant": new},
    }
    entry = {
        "entry_scope": {"entry_name": "vendor/Constants.class"},
        "member_deltas": [delta],
    }
    return {"entry_deltas": [entry] if entries else []}


class BinarySourceOverlayBoundaryTest(unittest.TestCase):
    def test_type_descriptor_and_method_descriptor_matrix(self):
        base = method()
        cases = (
            ("boolean", False, "Z"),
            ("byte[]", False, "[B"),
            ("final int", False, "I"),
            ("String...", False, "[Ljava/lang/String;"),
            ("java.util.List<String>[]", False, "[Ljava/util/List;"),
            ("? extends java.lang.Number", False, "Ljava/lang/Number;"),
            ("void", True, "V"),
            ("void[]", True, "[Ldemo/void;"),
            ("", False, ""),
            ("T", False, ""),
        )
        for raw, allow_void, expected in cases:
            with self.subTest(raw=raw, allow_void=allow_void):
                self.assertEqual(
                    overlay._source_type_descriptor(
                        raw, base, allow_void=allow_void
                    ),
                    expected,
                )

        known = method(known_classes_by_simple={"Known": "a.b.Known"})
        imported = method(imports={"Imported": "c.d.Imported"})
        no_package = method(package_name="")
        self.assertEqual(
            overlay._source_type_descriptor("Known", known), "La/b/Known;"
        )
        self.assertEqual(
            overlay._source_type_descriptor("Imported", imported),
            "Lc/d/Imported;",
        )
        self.assertEqual(
            overlay._source_type_descriptor("Local", base), "Ldemo/Local;"
        )
        self.assertEqual(overlay._source_type_descriptor("Local", no_package), "")

        descriptor_method = method(
            class_name="Outer.Inner",
            method_name="Inner",
            param_types={"a": "long", "b": "Object"},
            param_declared_types={"a": "int", "b": ""},
            return_type="ignored.Type",
        )
        self.assertEqual(overlay.source_method_descriptor(descriptor_method), "(ILjava/lang/Object;)V")
        self.assertEqual(
            overlay.source_method_descriptor(method(
                param_types={"a": "T"}, return_type="String"
            )),
            "",
        )
        self.assertEqual(
            overlay.source_method_descriptor(method(return_type="T")), ""
        )
        self.assertEqual(
            overlay.source_method_descriptor(method(
                param_types=None, param_declared_types=None,
                return_declared_type="String", return_type="",
            )),
            "()Ljava/lang/String;",
        )
        self.assertEqual(
            overlay.source_method_descriptor(method(
                class_name=None, method_name=None, return_type="void"
            )),
            "()V",
        )

    def test_owner_and_method_normalization_matrix(self):
        self.assertEqual(overlay._normalized_binary_owner(None), "")
        self.assertEqual(overlay._normalized_binary_owner("a/B$C"), "a.B.C")
        self.assertEqual(overlay._normalized_source_owner(method(class_fqcn=None)), "")
        self.assertEqual(
            overlay._normalized_source_owner(method(class_fqcn="a.B$C")), "a.B.C"
        )
        self.assertEqual(
            overlay._source_method_name(method(method_name=None, class_name=None)), ""
        )
        self.assertEqual(
            overlay._source_method_name(method(method_name="Sample", class_name="a.Sample")),
            "<init>",
        )
        self.assertEqual(overlay._source_method_name(method(method_name="run")), "run")

    def test_java_comment_and_literal_stripping_state_machine(self):
        source = (
            "int a = 1 / 2; // hidden VALUE\n"
            "/* block\nVALUE */ int b = 2; "
            "String s = \"VALUE \\\" escaped\"; "
            "char c = '\\''; VALUE;"
        )
        stripped = overlay._strip_java_comments_and_literals(source)
        self.assertEqual(len(stripped), len(source))
        self.assertEqual(stripped.count("\n"), source.count("\n"))
        self.assertIn("int a = 1 / 2;", stripped)
        self.assertIn("VALUE;", stripped)
        self.assertNotIn("hidden VALUE", stripped)
        self.assertNotIn("block\nVALUE", stripped)

        for fragment in (
            "// no newline",
            "/* unterminated",
            "\"unterminated\\",
            "\"line one\nline two\"",
            "'x'",
            "/* *x **/",
            "\"\"",
            "/",
            "",
        ):
            with self.subTest(fragment=fragment):
                result = overlay._strip_java_comments_and_literals(fragment)
                self.assertEqual(len(result), len(fragment))

    def test_exact_field_reference_count_alias_static_import_and_boundaries(self):
        non_java = method(language="kotlin", body="Constants.VALUE")
        self.assertEqual(
            overlay._exact_field_reference_count(non_java, "vendor/Constants", "VALUE"),
            0,
        )
        self.assertEqual(
            overlay._exact_field_reference_count(
                method(language=None, body="Constants.VALUE"),
                "vendor/Constants", "VALUE",
            ),
            0,
        )
        java = method(
            imports={"Alias": "vendor.Constants", "Other": "x.Other"},
            static_imports={"VALUE": "vendor.Constants.VALUE"},
            body=(
                "Constants.VALUE + vendor.Constants.VALUE + Alias.VALUE + VALUE + "
                "obj.Constants.VALUE2 + \"Constants.VALUE\" // Alias.VALUE\n"
                "/* VALUE */"
            ),
        )
        self.assertEqual(
            overlay._exact_field_reference_count(java, "vendor/Constants", "VALUE"),
            4,
        )
        no_static = method(
            imports=None,
            static_imports={"VALUE": "other.Constants.VALUE"},
            body="VALUE Constants.VALUE",
        )
        self.assertEqual(
            overlay._exact_field_reference_count(no_static, "vendor/Constants", "VALUE"),
            1,
        )
        self.assertEqual(
            overlay._exact_field_reference_count(
                method(static_imports=None, body="nothing"),
                "vendor/Outer$Constants",
                "VALUE",
            ),
            0,
        )

    def test_instruction_constant_extraction_matrix(self):
        target = member("consumer")
        self.assertEqual(overlay._instruction_constants(Store(classes=[]), target), Counter())
        duplicate = Store(classes=[
            {"class_variant_identity": "variant", "fact_json": "{}"},
            {"class_variant_identity": "variant", "fact_json": "{}"},
        ])
        self.assertEqual(overlay._instruction_constants(duplicate, target), Counter())

        fact = {
            "methods": [
                {"contract": None, "instructions": [["ldc", 0, "ignored"]]},
                {"contract": {"name": "other", "descriptor": "()V"}, "instructions": []},
                {"contract": {"name": "run", "descriptor": "(I)V"}, "instructions": []},
                {
                    "contract": {"name": "run", "descriptor": "()V"},
                    "instructions": [
                        None,
                        ["ldc"],
                        ["ldc", 0, {"kind": "type"}],
                        ["ldc", 0, "text"],
                        ["ldc", 0, 4],
                        ["int", 0, 16, 120],
                        ["int", 0, 16],
                        ["int", 0, 17, -4],
                        ["int", 0, 18, 99],
                        ["insn", 0, 2],
                        ["insn", 0, 7],
                        ["insn", 0, 8],
                        ["insn", 0, 11],
                        ["insn", 0, 200],
                        ["other", 0, 1],
                    ],
                },
            ]
        }
        store = Store(classes=[{
            "class_variant_identity": "variant",
            "fact_json": json.dumps(fact),
        }])
        constants = overlay._instruction_constants(store, target)
        self.assertEqual(constants[("str", "text")], 1)
        self.assertEqual(constants[("int", 4)], 2)
        self.assertEqual(constants[("int", 120)], 1)
        self.assertEqual(constants[("int", -4)], 1)
        self.assertEqual(constants[("int", -1)], 1)
        self.assertEqual(constants[("int", 5)], 1)
        self.assertEqual(constants[("float", 0.0)], 1)

        no_match = Store(classes=[{
            "class_variant_identity": "variant", "fact_json": json.dumps({"methods": []})
        }])
        self.assertEqual(overlay._instruction_constants(no_match, target), Counter())

    def test_build_source_overlay_identity_location_and_status_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            good = root / "Good.java"
            good.write_text("class Good {}", encoding="utf-8")
            missing = root / "Missing.java"
            outside = root.parent / "Outside.java"

            good_method = method(
                symbol_id="good", file=str(good), source_root=str(root),
                line=1, end_line=2, language="java", owner_type="business",
                owner_coord="coord", module="module",
            )
            missing_method = method(
                symbol_id="missing", method_name="missing",
                file=str(missing), source_root=str(root),
            )
            outside_method = method(
                symbol_id="outside", method_name="outside",
                file=str(outside), source_root=str(root),
            )
            duplicate_one = method(symbol_id="a", method_name="duplicate")
            duplicate_two = method(symbol_id=None, method_name="duplicate")
            mismatch = method(
                symbol_id="mismatch", method_name="mismatch",
                param_types={"value": "long"},
            )
            invalid = method(
                symbol_id="invalid", method_name="mismatch",
                param_types={"value": "T"},
            )
            constructor = method(
                symbol_id="ctor", method_name="Sample", class_name="Sample",
                file=str(good), source_root=str(root),
            )
            empty_meta = method(
                symbol_id=None, method_name="emptyMeta", file=str(good),
                source_root=str(root), line=None, end_line=None, language=None,
                owner_type=None, owner_coord=None, module=None,
            )
            empty_paths = method(
                symbol_id="empty-paths", method_name="emptyPaths",
                file=None, source_root=None,
            )
            methods = [
                good_method, missing_method, outside_method,
                duplicate_one, duplicate_two, mismatch, invalid, constructor,
                empty_meta, empty_paths,
            ]
            members = [
                member("mapped"),
                member("missing", name="missing"),
                member("outside", name="outside"),
                member("ambiguous", name="duplicate"),
                member("mismatch", name="mismatch", descriptor="(I)V"),
                member("bridge", name="bridge", access_flags=overlay.ACC_BRIDGE),
                member("synthetic", name="synthetic", access_flags=overlay.ACC_SYNTHETIC),
                member("clinit", name="<clinit>"),
                member("binary-only", name="unavailable"),
                member("constructor", name="<init>"),
                member("empty-meta", name="emptyMeta"),
                member("empty-paths", name="emptyPaths"),
            ]
            store = Store(
                members=members,
                artifact_instances=[
                    {"artifact_instance_identity": "artifact", "coord": None}
                ],
            )
            result = overlay.build_source_overlay(
                store, methods,
                analysis_context_identity=" context ",
                source_snapshot_identity=" snapshot ",
                source_snapshot_coverage_status="complete",
            )
            statuses = {row["binary_member_identity"]: row for row in result.rows}
            self.assertEqual(statuses["mapped"]["mapping_status"], "mapped")
            self.assertEqual(
                statuses["missing"]["conflict"]["reason_code"], "SOURCE_FILE_MISSING"
            )
            self.assertEqual(
                statuses["outside"]["conflict"]["reason_code"],
                "SOURCE_LOCATION_OUTSIDE_SNAPSHOT_ROOT",
            )
            self.assertEqual(statuses["ambiguous"]["mapping_status"], "ambiguous")
            self.assertEqual(
                statuses["ambiguous"]["conflict"]["candidate_symbol_ids"], ["", "a"]
            )
            self.assertEqual(
                statuses["mismatch"]["conflict"]["source_descriptors"],
                ["(J)V", "unknown"],
            )
            for identity in ("bridge", "synthetic", "clinit"):
                self.assertEqual(
                    statuses[identity]["conflict"]["reason_code"],
                    "COMPILER_GENERATED_MEMBER",
                )
            self.assertEqual(
                statuses["binary-only"]["conflict"]["reason_code"],
                "SOURCE_METHOD_NOT_AVAILABLE",
            )
            self.assertEqual(statuses["constructor"]["mapping_status"], "mapped")
            self.assertEqual(statuses["empty-meta"]["mapping_status"], "mapped")
            self.assertEqual(
                statuses["empty-paths"]["conflict"]["reason_code"],
                "SOURCE_FILE_MISSING",
            )
            self.assertEqual(statuses["mapped"]["binary_member"]["artifact_coord"], "")
            self.assertEqual(result.coverage_status, "partial")
            self.assertEqual(len(store.source_rows), len(members))

            partial_store = Store(members=[], artifact_instances=[])
            partial = overlay.build_source_overlay(
                partial_store, [], analysis_context_identity="c",
                source_snapshot_identity="s", source_snapshot_coverage_status="partial",
            )
            self.assertEqual(partial.coverage_status, "partial")

        for context, snapshot in (("", "snapshot"), ("context", ""), (None, None)):
            with self.subTest(context=context, snapshot=snapshot):
                with self.assertRaises(overlay.SourceOverlayError):
                    overlay.build_source_overlay(
                        Store(members=[], artifact_instances=[]), [],
                        analysis_context_identity=context,
                        source_snapshot_identity=snapshot,
                    )

    def _inline_inputs(self, consumers, methods, *, coverage="complete"):
        field = member(
            "field", owner="vendor/Constants", name="VALUE", descriptor="I",
            member_kind="field", class_variant_identity="field-v",
        )
        current = Store(members=[field, *consumers], direct_edges=[{"edge": "field"}])
        base = Store(members=[])
        source_rows = tuple({
            "mapping_status": "mapped",
            "binary_member_identity": consumer["member_identity"],
            "source_location": {"source_symbol_id": source.symbol_id},
            "overlay_identity": "overlay-" + consumer["member_identity"],
        } for consumer, source in zip(consumers, methods))
        source_overlay = overlay.SourceOverlayResult(
            source_snapshot_identity="snapshot",
            overlay_set_identity="set",
            rows=source_rows,
            mapped_count=len(source_rows), ambiguous_count=0,
            binary_only_count=0, conflict_count=0,
            coverage_status=coverage,
        )
        selected = [
            {"selected_class_variant_identity": value, "class_provider_status": "resolved"}
            for value in {"field-v", *(item["class_variant_identity"] for item in consumers)}
        ]
        selected.append({
            "selected_class_variant_identity": "ignored",
            "class_provider_status": "ambiguous",
        })
        reconciliation = SimpleNamespace(provider_bindings=selected)
        return base, current, source_overlay, reconciliation

    def test_inline_overlay_all_consumption_states(self):
        consumers = [
            member("physical", name="physical", class_variant_identity="p-v"),
            member(
                "unchanged", name="unchanged", class_variant_identity="u-v",
                implementation_digest="same",
            ),
            member("proven", name="proven", class_variant_identity="t-v"),
            member("possible", name="possible", class_variant_identity="q-v"),
        ]
        methods = [
            method(symbol_id=item["member_identity"], method_name=item["member_name"], body="Constants.VALUE")
            for item in consumers
        ]
        base, current, source_overlay, reconciliation = self._inline_inputs(
            consumers, methods
        )
        base.tables["members"] = [
            member(
                "base-" + item["member_identity"], name=item["member_name"],
                class_variant_identity="base-" + item["class_variant_identity"],
                implementation_digest=(
                    "same" if item["member_identity"] == "unchanged" else "base-digest"
                ),
            )
            for item in consumers
        ]
        current.physical_consumers.add("physical")

        def constants(_store, row):
            identity = row["member_identity"]
            if identity in {"base-proven", "base-possible"}:
                return Counter({("int", 1): 1})
            if identity in {"proven", "possible"}:
                return Counter({("int", 2): 1})
            return Counter()

        def references(source, _owner, _name):
            return 2 if source.symbol_id == "possible" else 1

        with patch.object(overlay, "_instruction_constants", side_effect=constants), \
                patch.object(overlay, "_exact_field_reference_count", side_effect=references):
            result = overlay.build_inline_consumption_overlay(
                base, current, methods, source_overlay, [field_diff()], reconciliation,
                analysis_context_identity="context",
            )
        states = {row["consumer_member_identity"]: row for row in result.rows}
        self.assertEqual(states["physical"]["consumption_state"], "not_inlined_binary_field_access")
        self.assertEqual(states["unchanged"]["consumption_state"], "retained_base_or_unchanged")
        self.assertEqual(states["proven"]["binding_certainty"], "proven")
        self.assertEqual(states["possible"]["binding_certainty"], "possible")
        self.assertEqual(states["proven"]["base_consumer_member_identity"], "base-proven")
        self.assertEqual(result.proven_count, 1)
        self.assertEqual(result.possible_count, 1)
        self.assertEqual(result.retained_or_unchanged_count, 1)
        self.assertEqual(result.coverage_status, "complete")
        self.assertEqual(len(current.inline_rows), 4)

    def test_inline_overlay_unbound_partial_and_nonqualifying_changes(self):
        consumer = member("consumer", class_variant_identity="consumer-v")
        source = method(symbol_id="consumer", body="no field reference")
        base, current, source_overlay, reconciliation = self._inline_inputs(
            [consumer], [source], coverage="partial"
        )
        base.tables["members"] = [
            member("base-one", class_variant_identity="base-1"),
            member("base-two", class_variant_identity="base-2"),
        ]
        with patch.object(overlay, "_exact_field_reference_count", return_value=0):
            result = overlay.build_inline_consumption_overlay(
                base, current, [source], source_overlay, [field_diff()], reconciliation,
                analysis_context_identity="context",
            )
        self.assertEqual(result.unbound_count, 1)
        self.assertEqual(result.rows[0]["reason_code"], "NO_EXACT_SOURCE_SYMBOL_REFERENCE_IN_OVERLAY")
        self.assertEqual(result.coverage_status, "partial")

        no_changes = [
            field_diff(entries=False),
            field_diff(kind="method"),
            field_diff(access=0),
            field_diff(old=1, new=1),
            field_diff(old=None, new=2),
            field_diff(old=1, new=None),
            {"entry_deltas": [{"entry_scope": {}, "member_deltas": [{}]}]},
            {"entry_deltas": [{
                "entry_scope": {},
                "member_deltas": [{
                    "member_scope": {"member_kind": "field"},
                    "base_contract": None,
                    "current_contract": {"access": 0},
                }],
            }]},
            {"entry_deltas": [{
                "entry_scope": {},
                "member_deltas": [{
                    "member_scope": {"member_kind": "field"},
                    "base_contract": {"access": 0},
                    "current_contract": None,
                }],
            }]},
            {"entry_deltas": None},
            {"entry_deltas": [{"entry_scope": {}, "member_deltas": None}]},
        ]
        empty = overlay.build_inline_consumption_overlay(
            Store(members=[]), Store(members=[]), [method(symbol_id=None)],
            overlay.SourceOverlayResult("s", "o", (), 0, 0, 0, 0, "complete"),
            no_changes,
            SimpleNamespace(provider_bindings=[]),
            analysis_context_identity="context",
        )
        self.assertEqual(empty.rows, ())
        self.assertEqual(empty.coverage_status, "not_applicable")

        missing_field = overlay.build_inline_consumption_overlay(
            Store(members=[]), Store(members=[]), [],
            overlay.SourceOverlayResult("s", "o", (), 0, 0, 0, 0, "complete"),
            [field_diff()],
            SimpleNamespace(provider_bindings=[{
                "selected_class_variant_identity": None,
                "class_provider_status": "resolved",
            }]),
            analysis_context_identity="context",
        )
        self.assertEqual(missing_field.rows, ())
        self.assertEqual(missing_field.coverage_status, "partial")

    def test_inline_mapping_filters_missing_symbols_members_and_unselected_consumers(self):
        selected_consumer = member("selected", class_variant_identity="selected-v")
        unselected_consumer = member("unselected", class_variant_identity="unselected-v")
        source = method(symbol_id="selected", body="Constants.VALUE")
        base, current, source_overlay, reconciliation = self._inline_inputs(
            [selected_consumer, unselected_consumer], [source, method(symbol_id="unselected")]
        )
        source_overlay = overlay.SourceOverlayResult(
            "s", "o",
            (
                {"mapping_status": "binary_only"},
                {"mapping_status": "mapped", "binary_member_identity": "missing", "source_location": {}},
                {
                    "mapping_status": "mapped",
                    "binary_member_identity": "selected",
                    "source_location": {"source_symbol_id": "absent"},
                },
                *source_overlay.rows,
            ),
            2, 0, 1, 0, "partial",
        )
        reconciliation.provider_bindings = [
            item for item in reconciliation.provider_bindings
            if item.get("selected_class_variant_identity") != "unselected-v"
        ]
        with patch.object(overlay, "_exact_field_reference_count", return_value=1):
            result = overlay.build_inline_consumption_overlay(
                base, current, [source, method(symbol_id="unselected")],
                source_overlay, [field_diff()], reconciliation,
                analysis_context_identity="context",
            )
        self.assertEqual(result.unbound_count, 0)
        self.assertEqual(len(result.rows), 1)
        self.assertEqual(result.rows[0]["consumer_member_identity"], "selected")
        self.assertEqual(result.rows[0]["coverage_status"], "partial")
        self.assertEqual(result.rows[0]["base_consumer_member_identity"], "")

        complete_overlay = overlay.SourceOverlayResult(
            source_overlay.source_snapshot_identity,
            source_overlay.overlay_set_identity,
            source_overlay.rows,
            source_overlay.mapped_count,
            source_overlay.ambiguous_count,
            source_overlay.binary_only_count,
            source_overlay.conflict_count,
            "complete",
        )
        with patch.object(overlay, "_exact_field_reference_count", return_value=1):
            complete_without_base = overlay.build_inline_consumption_overlay(
                base, current, [source, method(symbol_id="unselected")],
                complete_overlay, [field_diff()], reconciliation,
                analysis_context_identity="context",
            )
        self.assertEqual(complete_without_base.rows[0]["coverage_status"], "partial")


if __name__ == "__main__":
    unittest.main()
