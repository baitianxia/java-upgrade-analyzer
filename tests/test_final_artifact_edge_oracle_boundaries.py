from __future__ import annotations

import io
import errno
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import final_artifact_edge_oracle as oracle


def _u2(value: int) -> bytes:
    return int(value).to_bytes(2, "big")


def _cp_utf8(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"\x01" + _u2(len(encoded)) + encoded


def _minimal_inventory_class(
    extra_entries=(), *, this_class: int = 2, trailing: bytes = b"",
) -> bytes:
    """Build a parseable class with optional ``(bytes, CP-slot-count)`` rows."""
    base_entries = (
        (_cp_utf8("fixture/Boundary"), 1),
        (b"\x07" + _u2(1), 1),
        (_cp_utf8("java/lang/Object"), 1),
        (b"\x07" + _u2(3), 1),
    )
    entries = (*base_entries, *tuple(extra_entries))
    constant_pool_count = 1 + sum(slots for _content, slots in entries)
    return b"".join((
        b"\xca\xfe\xba\xbe",
        _u2(0),
        _u2(52),
        _u2(constant_pool_count),
        *(content for content, _slots in entries),
        _u2(0x0021),
        _u2(this_class),
        _u2(4),
        _u2(0),
        _u2(0),
        _u2(0),
        _u2(0),
        trailing,
    ))


def _zip_bytes(entries) -> bytes:
    destination = io.BytesIO()
    with zipfile.ZipFile(destination, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return destination.getvalue()


class FinalArtifactEdgeOracleBoundaryTest(unittest.TestCase):
    def test_modified_utf8_rejects_each_three_byte_corruption(self):
        self.assertEqual(oracle._decode_modified_utf8(b"A\xc0\x80B"), "A\x00B")
        self.assertEqual(oracle._decode_modified_utf8("组合".encode("utf-8")), "组合")
        invalid_values = (
            b"\xe0\x20\x80",
            b"\xe0\xa0\x20",
            b"\xe0\x80\x80",
            b"\xf0\x90\x80\x80",
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(UnicodeDecodeError):
                oracle._decode_modified_utf8(value)

    def test_selected_target_normalization_covers_missing_duplicate_and_classifier_values(self):
        targets = oracle._normalize_selected_targets([
            None,
            "truthy-non-mapping",
            7,
            ["list"],
            {},
            {"owner": ""},
            {"owner": "a/b", "member": ""},
            {"owner": " a/b ", "member": " call ", "descriptor": None},
            {"owner": "a.b", "member": "call", "descriptor": " ()V "},
            {"owner": "a/b", "member": "call", "descriptor": ""},
        ])
        self.assertEqual(targets, (("a.b", "call", ""), ("a.b", "call", "()V")))
        self.assertEqual(oracle._normalize_selected_targets(None), ())

    def test_entry_reference_prefilter_covers_content_and_file_failures(self):
        target = {("vendor.Target", "call", "()V")}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = oracle.PackagedClass("Missing.class", root / "missing.class")
            self.assertTrue(oracle._entry_might_reference(missing, target))

            cases = (
                (b"vendor/Target call ()V", target, True),
                (b"other/Target call ()V", target, False),
                (b"vendor/Target other ()V", target, False),
                (b"vendor/Target call (I)V", target, False),
                (b"vendor/Target call", {("vendor.Target", "call", "")}, True),
                (b"anything", set(), False),
            )
            for content, selected, expected in cases:
                entry = oracle.PackagedClass("Entry.class", root / "unused.class", content)
                with self.subTest(content=content, selected=selected):
                    self.assertEqual(
                        oracle._entry_might_reference(entry, selected), expected,
                    )

    def test_edge_target_and_reverse_closure_cover_empty_partial_and_chained_edges(self):
        exact = {("vendor.Target", "call", "()V")}
        wildcard = {("vendor.Target", "call", "")}
        edge = {
            "caller_owner": "app.Middle",
            "caller_member": "bridge",
            "caller_descriptor": "()V",
            "callee_owner": "vendor.Target",
            "callee_member": "call",
            "callee_descriptor": "()V",
        }
        self.assertTrue(oracle._edge_targets(edge, exact))
        self.assertTrue(oracle._edge_targets(edge, wildcard))
        self.assertFalse(oracle._edge_targets(edge, {("vendor.Target", "other", "()V")}))
        self.assertFalse(oracle._edge_targets({}, exact))
        self.assertFalse(oracle._edge_targets(edge, set()))

        root_edge = {
            "caller_owner": "app.Root",
            "caller_member": "start",
            "caller_descriptor": "()V",
            "callee_owner": "app.Middle",
            "callee_member": "bridge",
            "callee_descriptor": "()V",
        }
        unrelated = {"callee_owner": "other.Type", "callee_member": "noop"}
        self.assertEqual(oracle._reverse_target_closure([], exact), [])
        self.assertEqual(oracle._reverse_target_closure([edge], set()), [])
        self.assertEqual(
            oracle._reverse_target_closure([unrelated, root_edge, edge], exact),
            [root_edge, edge],
        )
        blank_caller = dict(edge, caller_owner=None, caller_member=None, caller_descriptor=None)
        self.assertEqual(oracle._reverse_target_closure([blank_caller], exact), [blank_caller])

    def test_javap_identifier_unquoting_and_generic_prefix_matrix(self):
        identifier_cases = (
            (None, None),
            ("", None),
            ("plain", "plain"),
            ('bad"quote', None),
            ('"unterminated', None),
            ('""', None),
            ('"space name"', "space name"),
            ('"quote\\\"name"', 'quote"name'),
            ('"bad\\x"', None),
        )
        for value, expected in identifier_cases:
            with self.subTest(identifier=value):
                self.assertEqual(oracle._unquote_javap_identifier(value), expected)

        generic_cases = (
            ("", ""),
            ("java.lang.String", "java.lang.String"),
            ("<T> T call", "T call"),
            ("<T extends java.util.List<java.lang.String>> T call", "T call"),
            ("<T", "<T"),
            ("<> call", "call"),
        )
        for value, expected in generic_cases:
            with self.subTest(generic=value):
                self.assertEqual(oracle._strip_leading_type_parameters(value), expected)

        self.assertEqual(oracle._strip_member_modifiers(""), "")
        self.assertEqual(
            oracle._strip_member_modifiers("public static final <T> T call"),
            "T call",
        )
        self.assertEqual(oracle._strip_member_modifiers("java.lang.String value"), "java.lang.String value")

    def test_member_name_parser_covers_constructor_generics_quotes_and_invalid_declarations(self):
        cases = (
            ("", "pkg.Owner", False, None),
            ("public pkg.Owner", "pkg.Owner", True, "<init>"),
            ("public Owner", "pkg.Owner", True, "<init>"),
            ("public void call", "pkg.Owner", True, "call"),
            ("public <T extends java.util.List<java.lang.String>> T call", "pkg.Owner", True, "call"),
            ('public void "space name"', "pkg.Owner", True, "space name"),
            ("call", "pkg.Owner", True, None),
            ('public void "unterminated', "pkg.Owner", True, None),
            ('public void "escaped\\\" name"', "pkg.Owner", True, 'escaped" name'),
        )
        for declaration, owner, method, expected in cases:
            with self.subTest(declaration=declaration):
                self.assertEqual(
                    oracle._member_name_from_declaration(
                        declaration, owner, method=method,
                    ),
                    expected,
                )

    def test_unquoted_search_and_member_header_matrix(self):
        self.assertEqual(oracle._find_unquoted("", "="), -1)
        self.assertEqual(oracle._find_unquoted('"left=right" = value', "="), 13)
        self.assertEqual(oracle._find_unquoted('"escaped\\\"=still quoted"=x', "="), 24)
        self.assertEqual(oracle._find_unquoted("abc", "b", start=3), -1)
        self.assertEqual(oracle._find_unquoted('"unterminated=', "="), -1)
        self.assertEqual(oracle._find_unquoted(r"raw\=value", "="), 4)

        cases = (
            ("public void call();", (None, None)),
            ("  static {};", ("<clinit>", "method")),
            ("  public int VALUE;", ("VALUE", "field")),
            ('  public java.lang.String VALUE = "x=y";', ("VALUE", "field")),
            ("  VALUE;", (None, "invalid")),
            ("  public void call(;", (None, "invalid")),
            ("  public void call() suffix;", (None, "invalid")),
            ("  public void call() throws java.lang.Exception;", ("call", "method")),
            ("  call();", (None, "invalid")),
        )
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(oracle._parse_member_header(line, "pkg.Owner"), expected)

    def test_qualified_member_matrix(self):
        self.assertEqual(
            oracle._parse_qualified_member("call", "pkg.Owner"),
            ("pkg.Owner", "call"),
        )
        self.assertEqual(
            oracle._parse_qualified_member("pkg/Target.call", "pkg.Owner"),
            ("pkg.Target", "call"),
        )
        self.assertIsNone(oracle._parse_qualified_member('"bad.call', "pkg.Owner"))
        self.assertIsNone(oracle._parse_qualified_member('pkg/Target.""', "pkg.Owner"))

    def test_field_descriptor_parser_covers_all_shape_and_dimension_boundaries(self):
        cases = (
            ("", 0, None),
            ("I", 0, 1),
            ("[I", 0, 2),
            ("[", 0, None),
            ("V", 0, None),
            ("Ljava/lang/String;", 0, 18),
            ("L;", 0, None),
            ("Ljava.lang.String;", 0, None),
            ("Ljava/[lang;", 0, None),
            ("Ljava//lang/String;", 0, None),
            ("Ljava/lang/String", 0, None),
            ("xI", 1, 2),
            ("I", 2, None),
            ("[" * 256 + "I", 0, None),
        )
        for value, start, expected in cases:
            with self.subTest(value=value[:20], start=start):
                self.assertEqual(oracle._field_descriptor_end(value, start), expected)

    def test_method_descriptor_and_type_owner_matrix(self):
        descriptor_cases = (
            ("", False),
            ("I", False),
            ("III", False),
            ("(", False),
            ("(I", False),
            ("(II", False),
            ("(I)", False),
            ("()", False),
            ("()V", True),
            ("()VV", False),
            ("(I)V", True),
            ("(V)V", False),
            ("(Ljava/lang/String;)Ljava/util/List;", True),
            ("(Ljava/lang/String)V", False),
            ("()Lbad", False),
        )
        for descriptor, expected in descriptor_cases:
            with self.subTest(descriptor=descriptor):
                self.assertEqual(oracle._is_method_descriptor(descriptor), expected)

        owner_cases = (
            (None, None),
            ("", None),
            ("I", None),
            ("III", None),
            ("(", None),
            ("(I", None),
            ("(II", None),
            ("(I)", None),
            ("()", None),
            ("()V", ()),
            ("(I[JDLjava/lang/String;Ljava/lang/String;)[Ljava/util/List;", ("java/lang/String", "java/util/List")),
            ("(V)V", None),
            ("(Ljava/lang/String)V", None),
            ("()Lbad", None),
            ("()Vx", None),
            ("(" + "J" * 128 + ")V", None),
            ("(" + "[" * 256 + "I)V", None),
        )
        for descriptor, expected in owner_cases:
            with self.subTest(owners=repr(descriptor)[:40]):
                self.assertEqual(oracle._method_type_reference_owners(descriptor), expected)

    def test_field_and_method_handle_owner_matrix(self):
        field_cases = (
            ("", None),
            ("V", None),
            ("I", ()),
            ("[[J", ()),
            ("Ljava/lang/String;", ("java/lang/String",)),
            ("[[Ljava/util/List;", ("java/util/List",)),
        )
        for descriptor, expected in field_cases:
            with self.subTest(field=descriptor):
                self.assertEqual(oracle._field_type_reference_owners(descriptor), expected)

        field_handle = ("owner", "VALUE", "Ljava/lang/String;", "REF_getStatic", None)
        method_handle = ("owner", "call", "(Ljava/lang/String;)V", "REF_invokeStatic", False)
        unknown_handle = ("owner", "call", "()V", "REF_unknown", None)
        self.assertEqual(oracle._method_handle_reference_owners(field_handle), ("java/lang/String",))
        self.assertEqual(oracle._method_handle_reference_owners(method_handle), ("java/lang/String",))
        self.assertIsNone(oracle._method_handle_reference_owners(unknown_handle))

    def test_bootstrap_class_symbolic_owner_matrix(self):
        cases = (
            (None, None),
            ("", None),
            ("java/lang/String", "java/lang/String"),
            ("[Ljava/lang/String;", "[Ljava/lang/String;"),
            ("[V", None),
            ("java.lang.String", None),
            ("java/[lang", None),
            ("java/lang;String", None),
            ("java//lang/String", None),
            ("/java/lang/String", None),
            ("java/lang/String/", None),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(oracle._bootstrap_class_symbolic_owner(value), expected)

    def test_member_and_field_reference_matrix(self):
        method_cases = (
            ("", None),
            ("Method pkg/Target.call:I", None),
            ("Method pkg/Target.call:()V", ("pkg.Target", "call", "()V", "method")),
            ("InterfaceMethod pkg/Target.call:(I)V", ("pkg.Target", "call", "(I)V", "interface_method")),
            ('Method pkg/Target."":()V', None),
        )
        for comment, expected in method_cases:
            with self.subTest(method=comment):
                self.assertEqual(oracle._parse_member_reference(comment, "pkg.Owner"), expected)

        field_cases = (
            ("", None),
            ("Field pkg/Target.VALUE:V", None),
            ("Field pkg/Target.VALUE:Ljava.lang.Bad;", None),
            ("Field pkg/Target.VALUE:I", ("pkg.Target", "VALUE", "I")),
            ('Field pkg/Target."":I', None),
        )
        for comment, expected in field_cases:
            with self.subTest(field=comment):
                self.assertEqual(oracle._parse_field_reference(comment, "pkg.Owner"), expected)

    def test_dynamic_constant_and_handle_tables_ignore_invalid_rows(self):
        output = "\n".join((
            "  #10 = InvokeDynamic #2:#3 // #3:call:(I)V",
            "  #11 = InvokeDynamic #2:#3 // #3:bad:I",
            "  #14 = InvokeDynamic #2:#3 // #3:bad:(I",
            "  #12 = Dynamic #4:#5 // #5:value:Ljava/lang/String;",
            "  #13 = Dynamic #4:#5 // #5:bad:V",
            "  #15 = Dynamic #4:#5 // #5:bad:Ljava.lang.Bad;",
            "  #20 = Methodref #1.#2 // owner.call:()V",
            "  #21 = InterfaceMethodref #1.#2 // owner.call:()V",
            "  #22 = Fieldref #1.#2 // owner.VALUE:I",
            "  #30 = MethodHandle 6:#20 // REF_invokeStatic owner.call:()V",
            "  #31 = MethodHandle 9:#21 // REF_invokeInterface owner.call:()V",
            "  #32 = MethodHandle 2:#22 // REF_getStatic owner.VALUE:I",
            "  #33 = MethodHandle 6:#99 // REF_invokeStatic missing.call:()V",
        ))
        self.assertEqual(oracle._dynamic_references(output), {10: (2, "call", "(I)V")})
        self.assertEqual(
            oracle._constant_dynamic_references(output),
            {12: (4, "value", "Ljava/lang/String;")},
        )
        self.assertEqual(
            oracle._method_handle_interfaces(output),
            {30: False, 31: True, 32: False},
        )


class FinalArtifactBootstrapBoundaryTest(unittest.TestCase):
    BOOTSTRAP = (
        "fixture.Bootstrap", "bootstrap", "()V", "REF_invokeStatic", False,
    )
    NESTED_BOOTSTRAP = (
        "fixture.Nested", "bootstrap", "()V", "REF_invokeStatic", False,
    )
    HANDLE = (
        "fixture.Target", "call", "()V", "REF_invokeStatic", False,
    )

    @classmethod
    def reference_set(
        cls,
        bootstrap=None,
        *,
        handles=(),
        constants=(),
        types=(),
    ):
        return oracle.BootstrapReferenceSet(
            bootstrap=bootstrap or cls.BOOTSTRAP,
            argument_handles=tuple(handles),
            constant_dynamic_arguments=tuple(constants),
            type_arguments=tuple(types),
        )

    @staticmethod
    def inventory(*, classes=(), method_types=(), tags=()):
        return oracle.ClassfileMemberInventory(
            owner="fixture/Caller",
            members=(),
            class_access_flags=0x21,
            major_version=52,
            super_class=4,
            interface_count=0,
            class_attributes=(),
            class_constants=tuple(classes),
            method_type_constants=tuple(method_types),
            constant_pool_tags=tuple(tags),
        )

    def test_recursive_bootstrap_handle_resolution_failure_and_success_matrix(self):
        functions = (
            oracle._bootstrap_argument_handles,
            oracle._bootstrap_resolution_handles,
        )
        for function in functions:
            with self.subTest(function=function.__name__, case="cycle"):
                values, failure = function(0, {}, {}, active_bootstraps=frozenset({0}))
                self.assertEqual(values, ())
                self.assertIn("cyclic", failure)
            with self.subTest(function=function.__name__, case="missing-root"):
                values, failure = function(0, {}, {})
                self.assertEqual(values, ())
                self.assertIn("unresolved bootstrap 0", failure)

            refs = {0: self.reference_set(constants=(100,))}
            with self.subTest(function=function.__name__, case="missing-constant"):
                values, failure = function(0, refs, {})
                self.assertEqual(values, ())
                self.assertIn("constant #100", failure)

            dynamics = {100: (1, "nested", "Ljava/lang/Object;")}
            with self.subTest(function=function.__name__, case="missing-nested"):
                values, failure = function(0, refs, dynamics)
                self.assertEqual(values, ())
                self.assertIn("bootstrap 1", failure)

            cyclic_refs = {
                0: self.reference_set(constants=(100,)),
                1: self.reference_set(
                    self.NESTED_BOOTSTRAP,
                    handles=(self.HANDLE,),
                    constants=(101,),
                ),
            }
            cyclic_dynamics = {
                100: (1, "nested", "Ljava/lang/Object;"),
                101: (0, "root", "Ljava/lang/Object;"),
            }
            with self.subTest(function=function.__name__, case="nested-cycle"):
                values, failure = function(0, cyclic_refs, cyclic_dynamics)
                self.assertEqual(values, ())
                self.assertIn("cyclic", failure)

            successful_refs = {
                0: self.reference_set(handles=(self.HANDLE,), constants=(100,)),
                1: self.reference_set(
                    self.NESTED_BOOTSTRAP, handles=(self.HANDLE,),
                ),
            }
            with self.subTest(function=function.__name__, case="success"):
                values, failure = function(0, successful_refs, dynamics)
                self.assertIsNone(failure)
                self.assertEqual(len(values), len(set(values)))
                self.assertIn(self.HANDLE, values)

    def test_recursive_bootstrap_type_resolution_failure_and_success_matrix(self):
        function = oracle._bootstrap_argument_types
        values, failure = function(0, {}, {}, active_bootstraps=frozenset({0}))
        self.assertEqual(values, ())
        self.assertIn("cyclic", failure)
        values, failure = function(0, {}, {})
        self.assertEqual(values, ())
        self.assertIn("unresolved bootstrap 0", failure)

        refs = {0: self.reference_set(constants=(100,))}
        values, failure = function(0, refs, {})
        self.assertEqual(values, ())
        self.assertIn("constant #100", failure)
        dynamics = {100: (1, "nested", "Ljava/lang/Object;")}
        values, failure = function(0, refs, dynamics)
        self.assertEqual(values, ())
        self.assertIn("bootstrap 1", failure)

        cyclic_refs = {
            0: self.reference_set(constants=(100,)),
            1: self.reference_set(self.NESTED_BOOTSTRAP, constants=(101,)),
        }
        cyclic_dynamics = {
            100: (1, "nested", "Ljava/lang/Object;"),
            101: (0, "root", "Ljava/lang/Object;"),
        }
        values, failure = function(0, cyclic_refs, cyclic_dynamics)
        self.assertEqual(values, ())
        self.assertIn("cyclic", failure)

        successful_refs = {
            0: self.reference_set(
                constants=(100,), types=(("type", "java/lang/String"),),
            ),
            1: self.reference_set(
                self.NESTED_BOOTSTRAP,
                types=(("method_type", "()Ljava/util/List;"),),
            ),
        }
        values, failure = function(0, successful_refs, dynamics)
        self.assertIsNone(failure)
        self.assertEqual(values, (
            ("type", "java/lang/String"),
            ("constant_dynamic", "Ljava/lang/Object;"),
            ("method_type", "()Ljava/util/List;"),
        ))

    def test_dynamic_reference_resolution_matrix(self):
        non_linker = {0: self.reference_set(handles=(self.HANDLE,))}
        linker = {
            0: self.reference_set(
                (
                    "java.lang.invoke.LambdaMetafactory", "metafactory", "()V",
                    "REF_invokeStatic", False,
                ),
                handles=(self.HANDLE,),
            )
        }
        cases = (
            ("", "", {}, {}, True, "unresolved"),
            ("", "InvokeDynamic #0:run:(I", {}, {}, True, "unresolved"),
            ("#8", "", {}, {}, True, "unresolved"),
            ("", "InvokeDynamic #0:run:()V", {}, {}, True, "bootstrap 0"),
            ("", "InvokeDynamic #0:run:()V", {}, non_linker, False, None),
            ("#8", "ignored", {8: (0, "run", "()V")}, linker, False, None),
        )
        for rest, comment, dynamics, refs, empty, failure_text in cases:
            with self.subTest(rest=rest, comment=comment, refs=bool(refs)):
                values, failure = oracle._parse_dynamic_reference(
                    rest, comment, dynamics, refs, {},
                )
                self.assertEqual(not bool(values), empty)
                if failure_text is None:
                    self.assertIsNone(failure)
                else:
                    self.assertIn(failure_text, failure)

        cyclic_refs = {0: self.reference_set(constants=(100,))}
        values, failure = oracle._parse_dynamic_reference(
            "#8", "", {8: (0, "run", "()V")}, cyclic_refs,
            {100: (0, "nested", "Ljava/lang/Object;")},
        )
        self.assertEqual(values, ())
        self.assertIn("cyclic", failure)

    def test_constant_dynamic_reference_resolution_matrix(self):
        refs = {0: self.reference_set(handles=(self.HANDLE,))}
        cases = (
            ("", "", {}, {}, "unresolved ConstantDynamic bootstrap or"),
            (
                "", "Dynamic #0:value:Ljava.lang.Bad;", {}, {},
                "unresolved ConstantDynamic bootstrap or",
            ),
            ("#8", "", {}, {}, "unresolved ConstantDynamic bootstrap or"),
            ("", "Dynamic #0:value:I", {}, {}, "bootstrap 0"),
            ("#8", "", {8: (0, "value", "I")}, {}, "bootstrap 0"),
        )
        for rest, comment, dynamics, references, failure_text in cases:
            with self.subTest(rest=rest, comment=comment):
                bootstrap, handles, failure = oracle._parse_constant_dynamic_reference(
                    rest, comment, dynamics, references,
                )
                self.assertIsNone(bootstrap)
                self.assertEqual(handles, ())
                self.assertIn(failure_text, failure)

        bootstrap, handles, failure = oracle._parse_constant_dynamic_reference(
            "", "Dynamic #0:value:I", {}, refs,
        )
        self.assertEqual(bootstrap, self.BOOTSTRAP)
        self.assertEqual(handles, (self.HANDLE,))
        self.assertIsNone(failure)

        cyclic_refs = {0: self.reference_set(constants=(100,))}
        bootstrap, handles, failure = oracle._parse_constant_dynamic_reference(
            "#8", "", {8: (0, "value", "I"), 100: (0, "nested", "I")},
            cyclic_refs,
        )
        self.assertIsNone(bootstrap)
        self.assertEqual(handles, ())
        self.assertIn("cyclic", failure)

    def test_ldc_handle_parser_rejects_each_invalid_dimension(self):
        cases = (
            ("", None),
            ("MethodHandle REF_unknown fixture/Target.call:()V", None),
            ("MethodHandle REF_getStatic fixture/Target.VALUE:V", None),
            ("MethodHandle REF_invokeStatic fixture/Target.call:I", None),
            ('MethodHandle REF_invokeStatic fixture/Target."":()V', None),
            (
                "MethodHandle REF_invokeStatic fixture/Target.call:()V",
                ("fixture.Target", "call", "()V", "REF_invokeStatic", True),
            ),
        )
        for comment, expected in cases:
            with self.subTest(comment=comment):
                self.assertEqual(
                    oracle._parse_ldc_handle_reference(comment, "caller.Owner", True),
                    expected,
                )

    def test_javap_constant_type_table_filters_invalid_quoted_class(self):
        output = "\n".join((
            "  #1 = Class #2 // java/lang/String",
            '  #3 = Class #4 // ""',
            '  #5 = Class #6 // "unterminated',
            "  #7 = MethodType #8 // ()Ljava/util/List;",
        ))
        classes, method_types = oracle._javap_constant_type_values(output)
        self.assertEqual(classes, {1: "java/lang/String"})
        self.assertEqual(method_types, {7: "()Ljava/util/List;"})

    def test_bootstrap_reference_parser_handles_missing_tags_duplicates_and_invalid_handles(self):
        self.assertEqual(
            oracle._bootstrap_references(
                "BootstrapMethods:\n  not-a-reference", {},
            ),
            {},
        )
        output = "\n".join((
            "BootstrapMethods:",
            "  REF_invokeStatic fixture/Before.call:()V",
            "  0: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    REF_invokeStatic fixture/Target.call:()V",
            "    REF_invokeStatic fixture/Target.call:()V",
            "  1: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "  1: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "  2: #20 REF_unknown fixture/Bootstrap.bootstrap:()V",
            "  3: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:I",
            '  4: #20 REF_invokeStatic fixture/Bootstrap."":()V',
            "OwnerAttribute:",
            "  5: #20 REF_invokeStatic fixture/Late.bootstrap:()V",
        ))
        references = oracle._bootstrap_references(output, {})
        self.assertEqual(set(references), {0})
        self.assertEqual(len(references[0].argument_handles), 1)
        self.assertEqual(references[0].argument_handles[0][4], None)

        tagged_output = "\n".join((
            "BootstrapMethods:",
            "  0: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    REF_invokeStatic fixture/Ignored.noConstant:()V",
            "    #21 REF_invokeStatic fixture/Ignored.wrongTag:()V",
            "    #22 REF_invokeStatic fixture/Target.call:()V",
            "  1: #21 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "  2: #23 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #24 REF_unknown fixture/Target.call:()V",
        ))
        inventory = self.inventory(tags=((20, 15), (21, 8), (22, 15), (23, 15), (24, 15)))
        references = oracle._bootstrap_references(tagged_output, {}, inventory)
        self.assertEqual(set(references), {0})
        self.assertEqual(
            references[0].argument_handles,
            (("fixture.Target", "call", "()V", "REF_invokeStatic", None),),
        )

    def test_bootstrap_reference_parser_validates_constant_dynamic_arguments(self):
        untagged = oracle._bootstrap_references(
            "\n".join((
                "BootstrapMethods:",
                "  0: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
                "    #30 #1:value:I",
            )),
            {30: (1, "value", "I")},
        )
        self.assertEqual(untagged[0].constant_dynamic_arguments, (30,))
        output = "\n".join((
            "BootstrapMethods:",
            "  0: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #30 #1:value:I",
            "    #30 #1:value:I",
            "  1: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #31 #1:value:I",
            "  2: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #30 #2:value:I",
            "  3: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #32 malformed-condy-rendering",
            "  4: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #33 REF_invokeStatic fixture/Target.call:I",
            "  5: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #34 malformed-method-handle",
        ))
        inventory = self.inventory(tags=(
            (20, 15), (30, 17), (31, 8), (32, 17), (33, 15), (34, 15),
        ))
        references = oracle._bootstrap_references(
            output,
            {
                30: (1, "value", "I"),
                31: (1, "value", "I"),
                32: (1, "value", "I"),
            },
            inventory,
        )
        self.assertEqual(set(references), {0})
        self.assertEqual(references[0].constant_dynamic_arguments, (30,))

    def test_bootstrap_reference_parser_cross_checks_method_type_arguments(self):
        output = "\n".join((
            "  #41 = MethodType #90 // (J)V",
            "  #42 = MethodType #91 // (I)V",
            "BootstrapMethods:",
            "  0: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #40 (J)V",
            "  1: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #41 (I)V",
            "  2: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #42 (I)V",
            "  3: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #43 bad",
            "  4: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #44 ()Ljava/lang/String;",
            "    #44 ()Ljava/lang/String;",
        ))
        inventory = self.inventory(
            method_types=(
                (40, "(I)V"),
                (41, "(I)V"),
                (42, "(I)V"),
                (43, "bad"),
                (44, "()Ljava/lang/String;"),
            ),
            tags=((20, 15),),
        )
        references = oracle._bootstrap_references(output, {}, inventory)
        self.assertEqual(set(references), {2, 4})
        self.assertEqual(
            references[4].type_arguments,
            (("method_type", "()Ljava/lang/String;"),),
        )

    def test_bootstrap_reference_parser_cross_checks_class_arguments(self):
        output = "\n".join((
            "  #41 = Class #90 // java/util/List",
            "  #42 = Class #91 // java/lang/String",
            "BootstrapMethods:",
            "  0: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #40 java/util/List",
            "  1: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #41 java/lang/String",
            "  2: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #42 java/lang/String",
            "  3: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            "    #43 java.lang.Bad",
            "  4: #20 REF_invokeStatic fixture/Bootstrap.bootstrap:()V",
            '    #44 "space name"',
            '    #44 "space name"',
        ))
        inventory = self.inventory(
            classes=(
                (40, "java/lang/String"),
                (41, "java/lang/String"),
                (42, "java/lang/String"),
                (43, "java.lang.Bad"),
                (44, "space name"),
            ),
            tags=((20, 15),),
        )
        references = oracle._bootstrap_references(output, {}, inventory)
        self.assertEqual(set(references), {2, 4})
        self.assertEqual(
            references[2].type_arguments,
            (("type", "java/lang/String"),),
        )
        self.assertEqual(references[4].type_arguments, (("type", "space name"),))


class FinalArtifactClassfileAndArchiveBoundaryTest(unittest.TestCase):
    def test_member_name_scanner_exercises_quoted_escape_and_generic_states(self):
        cases = (
            ('"quoted type" call', "call"),
            ('"quoted\\\" type" call', "call"),
            (r"raw\type call", "call"),
            ("java.util.Map<T, U> call", "call"),
            ("Type> call", "call"),
            ("<T extends java.util.List<U V>> T call", "call"),
            ('"unterminated type call', None),
        )
        for declaration, expected in cases:
            with self.subTest(declaration=declaration):
                self.assertEqual(
                    oracle._member_name_from_declaration(
                        declaration, "fixture.Owner", method=True,
                    ),
                    expected,
                )

    def test_method_type_owner_parser_rejects_each_object_name_and_return_boundary(self):
        cases = (
            ("(I", None),
            ("([)V", None),
            ("([[[)V", None),
            ("(L;)V", None),
            ("(Ljava.lang.String;)V", None),
            ("(Ljava/[lang;)V", None),
            ("(Ljava//lang/String;)V", None),
            ("(Ljava/lang/String)V", None),
            ("()Ljava.lang.String;", None),
            ("()[", None),
            ("()[Ljava/util/List;", ("java/util/List",)),
            ("([[[I)J", ()),
            ("(Ljava/lang/String;Ljava/lang/String;)V", ("java/lang/String",)),
        )
        for descriptor, expected in cases:
            with self.subTest(descriptor=descriptor):
                self.assertEqual(
                    oracle._method_type_reference_owners(descriptor), expected,
                )

    def test_class_reference_parser_covers_prefix_quote_escape_and_suffix_matrix(self):
        cases = (
            ("", None),
            ("not-class fixture/Type", None),
            ("class ", None),
            ("class fixture/Type", "fixture/Type"),
            ("class fixture/Type extra", None),
            ('class "space name"', "space name"),
            ('class "escaped\\\"name"', 'escaped"name'),
            ('class "unterminated', None),
            ('class "closed" suffix', None),
            ('class "bad\\x"', None),
        )
        for comment, expected in cases:
            with self.subTest(comment=comment):
                self.assertEqual(oracle._parse_class_reference(comment), expected)

    def test_logical_class_entry_and_effective_selection_matrix(self):
        logical_cases = (
            ("fixture/Base.class", ("fixture/Base.class", 0)),
            ("META-INF/ignored.class", None),
            ("fixture/not-a-class.txt", None),
            ("META-INF/versions/7/fixture/Base.class", None),
            ("META-INF/versions/8/fixture/Base.class", ("fixture/Base.class", 8)),
            ("META-INF/versions/9/fixture/Base.class", ("fixture/Base.class", 9)),
            ("META-INF/versions/9//fixture/Base.class", None),
            ("META-INF/versions/9/fixture/../Base.class", None),
            ("META-INF/versions/9/fixture/./Base.class", None),
            ("META-INF/versions/9/META-INF/Hidden.class", None),
            ("META-INF/versions/9/fixture/not-a-class.txt", None),
        )
        for name, expected in logical_cases:
            with self.subTest(name=name):
                self.assertEqual(
                    oracle._logical_class_entry(zipfile.ZipInfo(name)), expected,
                )

        base = zipfile.ZipInfo("fixture/Base.class")
        v9 = zipfile.ZipInfo("META-INF/versions/9/fixture/Base.class")
        v11 = zipfile.ZipInfo("META-INF/versions/11/fixture/Base.class")
        other_v9 = zipfile.ZipInfo("META-INF/versions/9/fixture/Only.class")
        junk = zipfile.ZipInfo("README.txt")
        cases = (
            ([], None, False, [], []),
            ([junk], None, False, [], []),
            ([base, v9], None, False, [base], []),
            ([v9], None, False, [], []),
            ([v9], None, True, [], ["cannot resolve"]),
            ([base], None, True, [base], []),
            ([v9], 8, True, [], []),
            ([v9], 9, True, [v9], []),
            ([base, v9, v11], 10, True, [v9], []),
            ([base, v9, v11], 11, True, [v11], []),
            ([base, v9, v9], 11, True, [], ["duplicate logical"]),
            ([base, v9, v9], 8, True, [base], []),
            ([base, other_v9], 9, True, [base, other_v9], []),
        )
        for infos, major, multi_release, selected, failure_fragments in cases:
            with self.subTest(
                names=[info.filename for info in infos],
                major=major,
                multi_release=multi_release,
            ):
                actual_selected, failures = oracle._select_effective_classes(
                    infos, major, "scope", multi_release,
                )
                self.assertEqual(actual_selected, selected)
                for fragment in failure_fragments:
                    self.assertTrue(any(fragment in failure for failure in failures))
                if not failure_fragments:
                    self.assertEqual(failures, [])

    def test_multi_release_manifest_recognition_matrix(self):
        cases = (
            ([], False),
            ([('META-INF/MANIFEST.MF', b'Multi-Release: true\r\n\r\n')], True),
            ([('META-INF/MANIFEST.MF', b'Multi-Release: false\r\n\r\n')], False),
            ([('META-INF/MANIFEST.MF', b'Multi-Release:true\r\n\r\n')], False),
            ([('META-INF/MANIFEST.MF', b'Multi-Release : true\r\n\r\n')], False),
            ([('META-INF/MANIFEST.MF', b' Multi-Release: true\r\n\r\n')], False),
            ([('META-INF/MANIFEST.MF', b'BadLine\r\nMulti-Release: true\r\n\r\n')], True),
            ([('META-INF/MANIFEST.MF', b'Name: value\r\n continued\r\nMulti-Release: true\r\n\r\n')], True),
            ([('META-INF/MANIFEST.MF', b'Multi-Release: tr\r\n ue\r\n\r\n')], False),
            ([('META-INF/MANIFEST.MF', b'\r\nMulti-Release: true\r\n')], False),
            ([('META-INF/MANIFEST.MF', b'x: y\r\n'), ('meta-inf/manifest.mf', b'x: z\r\n')], False),
            ([('META-INF/MANIFEST.MF', b'x: y')], False),
        )
        for entries, expected in cases:
            with self.subTest(entries=entries):
                with zipfile.ZipFile(io.BytesIO(_zip_bytes(entries))) as archive:
                    self.assertEqual(
                        oracle._is_multi_release_archive(archive), expected,
                    )

        bad_archive = Mock()
        manifest = zipfile.ZipInfo("META-INF/MANIFEST.MF")
        bad_archive.infolist.return_value = [manifest]
        bad_archive.read.side_effect = OSError("unreadable")
        self.assertFalse(oracle._is_multi_release_archive(bad_archive))

    def test_ambiguous_multi_release_manifest_failure_matrix(self):
        cases = (
            ([], False),
            ([('META-INF/MANIFEST.MF', b'')], False),
            ([('META-INF/MANIFEST.MF', b''), ('meta-inf/manifest.mf', b'')], False),
            ([('META-INF/MANIFEST.MF', b''), ('meta-inf/manifest.mf', b''), ('META-INF/versions/', b'')], False),
            ([('META-INF/MANIFEST.MF', b''), ('meta-inf/manifest.mf', b''), ('META-INF/versions/9/A.class', b'x')], True),
            ([('META-INF/MANIFEST.MF', b''), ('meta-inf/manifest.mf', b''), ('meta-inf/versions/9/A.class', b'x')], False),
        )
        for entries, expected_failure in cases:
            with self.subTest(entries=[name for name, _ in entries]):
                with zipfile.ZipFile(io.BytesIO(_zip_bytes(entries))) as archive:
                    failures = oracle._multi_release_manifest_failures(
                        archive, "scope",
                    )
                self.assertEqual(bool(failures), expected_failure)
                if failures:
                    self.assertIn("ambiguous", failures[0])

    def test_classfile_inventory_parses_primitive_long_handle_and_rejects_malformed_indexes(self):
        primitive_and_long = _minimal_inventory_class((
            (b"\x03" + b"\x00" * 4, 1),
            (b"\x04" + b"\x00" * 4, 1),
            (b"\x05" + b"\x00" * 8, 2),
            (b"\x06" + b"\x00" * 8, 2),
            (b"\x08" + _u2(1), 1),
            (b"\x13" + _u2(1), 1),
            (b"\x14" + _u2(1), 1),
            (b"\x0f" + b"\x01" + _u2(2), 1),
        ))
        inventory = oracle._classfile_member_inventory(primitive_and_long)
        self.assertEqual(inventory.owner, "fixture/Boundary")
        self.assertIn(15, dict(inventory.constant_pool_tags).values())

        malformed = [
            b"",
            b"not-a-classfile",
            b"\xca\xfe\xba\xbe" + _u2(0) + _u2(52) + _u2(0),
            primitive_and_long[:-1],
            _minimal_inventory_class(trailing=b"x"),
            _minimal_inventory_class(((b"\x07" + _u2(99), 1),)),
            _minimal_inventory_class(this_class=99),
        ]
        member_prefix = (
            (_cp_utf8("call"), 1),
            (_cp_utf8("()V"), 1),
            (b"\x0c" + _u2(5) + _u2(6), 1),
        )
        malformed.extend((
            _minimal_inventory_class((*member_prefix, (b"\x0a" + _u2(99) + _u2(7), 1))),
            _minimal_inventory_class((*member_prefix, (b"\x0a" + _u2(2) + _u2(99), 1))),
            _minimal_inventory_class(((b"\x63", 1),)),
            _minimal_inventory_class()[:-2]
            + _u2(1) + _u2(1) + (100).to_bytes(4, "big"),
        ))
        for content in malformed:
            with self.subTest(length=len(content)), self.assertRaises(ValueError):
                oracle._classfile_member_inventory(content)

    def test_classfile_header_and_module_descriptor_predicates_cover_fail_closed_paths(self):
        valid = _minimal_inventory_class()
        self.assertEqual(oracle._classfile_header_facts(valid), (False, 0x0021))
        self.assertEqual(
            oracle._classfile_header_facts(
                _minimal_inventory_class(((b"\x0f" + b"\x01" + _u2(2), 1),)),
            ),
            (True, 0x0021),
        )
        for content in (
            b"",
            b"not-a-class",
            b"\xca\xfe\xba\xbe" + _u2(0) + _u2(52) + _u2(0),
            _minimal_inventory_class(((b"\x03" + b"\x00" * 4, 1),))[:57],
            _minimal_inventory_class(((b"\x05" + b"\x00" * 8, 2),))[:59],
            _minimal_inventory_class(((b"\x63", 1),)),
        ):
            with self.subTest(length=len(content)):
                self.assertEqual(oracle._classfile_header_facts(content)[1], None)

        base = dict(
            owner="module-info",
            members=(),
            class_access_flags=oracle.ACC_MODULE,
            major_version=53,
            super_class=0,
            interface_count=0,
            class_attributes=("Module",),
            class_constants=(),
            method_type_constants=(),
            constant_pool_tags=(),
        )
        valid_inventory = oracle.ClassfileMemberInventory(**base)
        with patch.object(
            oracle, "_classfile_member_inventory", return_value=valid_inventory,
        ):
            self.assertTrue(oracle._classfile_is_valid_module_descriptor(b"x"))
        for changed in (
            {"class_access_flags": 0},
            {"major_version": 52},
            {"owner": "ordinary"},
            {"super_class": 1},
            {"interface_count": 1},
            {"members": (oracle.ClassfileMember("field", "x", "I", 0),)},
            {"class_attributes": ()},
            {"class_attributes": ("Module", "Unknown")},
        ):
            inventory = oracle.ClassfileMemberInventory(**(base | changed))
            with self.subTest(changed=changed), patch.object(
                oracle, "_classfile_member_inventory", return_value=inventory,
            ):
                self.assertFalse(oracle._classfile_is_valid_module_descriptor(b"x"))
        with patch.object(
            oracle, "_classfile_member_inventory", side_effect=ValueError("bad"),
        ):
            self.assertFalse(oracle._classfile_is_valid_module_descriptor(b"x"))


class FinalArtifactParserBoundaryTest(unittest.TestCase):
    @staticmethod
    def inventory(
        members=(), *, owner="fixture/Caller", lossy=False,
        method_types=(), classes=(), tags=(),
    ):
        return oracle.ClassfileMemberInventory(
            owner=owner,
            members=tuple(members),
            class_access_flags=0x21,
            major_version=52,
            super_class=4,
            interface_count=0,
            class_attributes=(),
            class_constants=tuple(classes),
            method_type_constants=tuple(method_types),
            constant_pool_tags=tuple(tags),
            javap_reference_text_lossy=lossy,
        )

    @staticmethod
    def method(name="call", descriptor="()V"):
        return oracle.ClassfileMember("method", name, descriptor, 0x0009)

    @staticmethod
    def field(name="VALUE", descriptor="I"):
        return oracle.ClassfileMember("field", name, descriptor, 0x0009)

    @staticmethod
    def wrapper(*instructions, header="  public void call();", descriptor="()V"):
        return "\n".join((
            "public class fixture.Caller {",
            header,
            f"    descriptor: {descriptor}",
            "    Code:",
            *(f"       {instruction}" for instruction in instructions),
            "}",
        ))

    def parse_direct(self, output, inventory=None):
        return oracle._parse_javap_output(
            output, "sha", "fixture/Caller.class", "javap 21", inventory,
        )

    def test_nest_host_attribute_is_not_reparsed_as_a_class_declaration(self):
        inventory = self.inventory(
            (self.method(),), owner="fixture/Outer$Inner",
        )
        output = "\n".join((
            "class fixture.Outer$Inner {",
            "  public void call();",
            "    descriptor: ()V",
            "}",
            "NestHost: class fixture/Outer",
        ))

        rows, direct_failures = self.parse_direct(output, inventory)
        structural = oracle.parse_structural_javap(output, inventory)

        self.assertEqual(rows, [])
        self.assertEqual(direct_failures, [])
        self.assertEqual(structural["failures"], set())
        self.assertEqual(structural["class_names"], {"fixture/Outer$Inner"})
        self.assertIn(
            ("fixture/Outer$Inner", "method", "call", "()V", 0x0009),
            structural["declared_members"],
        )

    def test_raw_member_inventory_binding_failure_matrix(self):
        cases = (
            (
                "public class fixture.Other {\n"
                "  public void call();\n    descriptor: ()V\n}",
                self.inventory((self.method(),)),
                "owner mismatch",
            ),
            (
                "public class fixture.Caller {\n"
                "  public void call();\n    descriptor: ()\n    WRONG\n}",
                self.inventory((self.method(descriptor="()\nV"),)),
                "descriptor continuation mismatch",
            ),
            (
                "public class fixture.Caller {\n"
                "  public void call();\n    descriptor: (I)V\n"
                "    descriptor: ()V\n}",
                self.inventory((self.method(),)),
                "descriptor mismatch",
            ),
            (
                "public class fixture.Caller {\n"
                "  public void call();\n    descriptor: ()V\n}",
                self.inventory(()),
                "unexpected member descriptor",
            ),
            (
                "public class fixture.Caller {\n"
                "  public fixture.Caller();\n    descriptor: (I)I\n}",
                self.inventory((self.method("<init>", "(I)I"),)),
                "constructor descriptor must return void",
            ),
            (
                "public class fixture.Caller {\n"
                "  public int VALUE;\n    descriptor: I\n}",
                self.inventory((self.field(),)),
                None,
            ),
            (
                "public class fixture.Caller {",
                self.inventory((self.method(),)),
                "inventory ended",
            ),
            (
                "public class fixture.Caller {\n"
                "  public void call();\n    descriptor: ()",
                self.inventory((self.method(descriptor="()\nV"),)),
                "ended inside a member descriptor",
            ),
            (
                "public class fixture.Caller {\n"
                "  public void call();\n    descriptor: ()V",
                self.inventory((self.method(),)),
                "no complete class body",
            ),
        )
        for output, inventory, fragment in cases:
            with self.subTest(fragment=fragment):
                _rows, failures = self.parse_direct(output, inventory)
                structural = oracle.parse_structural_javap(output, inventory)
                combined = [*failures, *structural["failures"]]
                if fragment is None:
                    self.assertFalse(any("descriptor" in item for item in combined))
                else:
                    self.assertTrue(any(fragment in item for item in combined), combined)

    def test_text_member_state_and_code_block_failure_matrix(self):
        outputs = (
            "",
            "public class fixture.Caller\n{\n}",
            "public class fixture.Caller {\n  public int VALUE;\n    descriptor: I\n    Code:\n}",
            "public class fixture.Caller {\n  VALUE;\n    descriptor: I\n    Code:\n}",
            "public class fixture.Caller {\n    descriptor: ()V\n    Code:\n}",
            "public class fixture.Caller {\n  public fixture.Caller();\n    descriptor: (I)I\n    Code:\n}",
            "public class fixture.Caller {\n  public void call();\n    Code:\n}",
            "public class fixture.Caller {\n  public void call();\n    descriptor: ()V\n    Code:\n       not-an-instruction\n       0: return\n}",
            'public class "" {\n  public void call();\n    descriptor: ()V\n}',
        )
        direct_failures = []
        structural_failures = []
        for output in outputs:
            _rows, failures = self.parse_direct(output)
            direct_failures.extend(failures)
            structural_failures.extend(oracle.parse_structural_javap(output)["failures"])
        self.assertTrue(any("no class declaration" in item for item in direct_failures))
        self.assertTrue(any("descriptor without" in item for item in direct_failures))
        self.assertTrue(any("constructor descriptor" in item for item in direct_failures))
        self.assertTrue(any("Code block" in item for item in direct_failures))
        self.assertTrue(any("Code block" in item for item in structural_failures))

    def test_direct_edge_instruction_failure_and_success_matrix(self):
        prefix = "\n".join((
            "  #10 = Dynamic #0:#1 // #1:value:I",
            "  #11 = InvokeDynamic #0:#1 // #1:run:()V",
        ))
        output = prefix + "\n" + self.wrapper(
            "0: ldc #10",
            "0: ldc #10 // not-a-Dynamic-comment",
            "1: ldc #99",
            "2: ldc #99 // Dynamic #0:value:I",
            "3: ldc // MethodHandle REF_invokeStatic fixture/Target.call:()V",
            "4: ldc #12 // MethodHandle REF_invokeStatic fixture/Target.call:I",
            "5: invokestatic #13",
            "6: getstatic #14 // Field fixture/Target.VALUE:Ljava.lang.Bad;",
            "7: getstatic #15 // Field fixture/Target.VALUE:I",
            "8: invokevirtual #16 // Method fixture/Target.call:()V",
            "9: invokeinterface #17 // InterfaceMethod fixture/Api.call:()V",
            "10: invokedynamic #11 // InvokeDynamic #0:run:()V",
        )
        rows, failures = self.parse_direct(output)
        self.assertTrue(any("missing constant-pool comment" in item for item in failures))
        self.assertTrue(any("unparseable ldc MethodHandle" in item for item in failures))
        self.assertTrue(any("unparseable getstatic" in item for item in failures))
        self.assertTrue(any("unresolved invokedynamic" in item for item in failures))
        self.assertEqual(
            {row["opcode_family"] for row in rows},
            {"ldc_handle", "getstatic", "invokevirtual", "invokeinterface"},
        )

    def test_structural_instruction_and_type_helper_failure_matrix(self):
        output = self.wrapper(
            "0: new #1 // class fixture/Type",
            "1: anewarray #2 // class \"space name\"",
            "2: checkcast #3 // class \"unterminated",
            "3: ldc #4 // class fixture/Literal",
            "4: ldc_w #5 // class bad name",
            "5: invokestatic #6 // Method fixture/Target.call:(Ljava/lang/String;)V",
            "6: getstatic #7 // Field fixture/Target.VALUE:Ljava/util/List;",
            "7: invokedynamic #11 // InvokeDynamic #0:run:()V",
        )
        reference_set = FinalArtifactBootstrapBoundaryTest.reference_set(
            handles=(("fixture.Target", "call", "bad", "REF_unknown", None),),
        )
        with patch.object(
            oracle, "_dynamic_references", return_value={11: (0, "run", "bad")},
        ), patch.object(
            oracle, "_bootstrap_references", return_value={0: reference_set},
        ), patch.object(
            oracle,
            "_bootstrap_argument_types",
            return_value=((
                ("method_type", "bad"),
                ("type", "java.lang.Bad"),
                ("constant_dynamic", "V"),
                ("unknown", "value"),
            ), None),
        ), patch.object(
            oracle,
            "_bootstrap_resolution_handles",
            return_value=((
                ("fixture.Target", "call", "bad", "REF_unknown", None),
            ), None),
        ):
            structural = oracle.parse_structural_javap(output)
        failures = structural["failures"]
        self.assertTrue(any("unparseable invokedynamic descriptor" in item for item in failures))
        self.assertTrue(any("unparseable invokedynamic MethodType" in item for item in failures))
        self.assertTrue(any("class constant" in item for item in failures))
        self.assertTrue(any("unknown invokedynamic type constant" in item for item in failures))
        self.assertTrue(any("MethodHandle descriptor" in item for item in failures))

        with patch.object(
            oracle, "_dynamic_references", return_value={11: (0, "run", "()V")},
        ), patch.object(
            oracle, "_bootstrap_references", return_value={0: reference_set},
        ), patch.object(
            oracle, "_bootstrap_argument_types", return_value=((), "type failure"),
        ), patch.object(
            oracle, "_bootstrap_resolution_handles", return_value=((), "handle failure"),
        ):
            structural = oracle.parse_structural_javap(
                self.wrapper(
                    "0: invokedynamic #11 // InvokeDynamic #0:run:()V",
                )
            )
        self.assertTrue(any("type failure" in item for item in structural["failures"]))
        self.assertTrue(any("handle failure" in item for item in structural["failures"]))

    def test_structural_ldc_dynamic_method_type_and_active_use_matrix(self):
        output = self.wrapper(
            "0: ldc #20 // MethodType (Ljava/lang/String;)V",
            "1: ldc // MethodType ()Ljava/util/List;",
            "2: ldc #21 // MethodType bad",
            "3: ldc #22 // Dynamic #0:value:Ljava/util/Map;",
            "4: ldc #23 // Dynamic malformed",
            "5: ldc // MethodHandle REF_getStatic fixture/Target.VALUE:Ljava/time/Instant;",
            "6: ldc #24 // MethodHandle REF_getStatic fixture/Target.VALUE:V",
            "7: ldc #25 // class fixture/Literal",
            "8: ldc_w #26 // class bad name",
            "9: ldc2_w #27 // class fixture/NotALiteral",
            "10: invokedynamic // InvokeDynamic #0:run:()V",
            "11: invokedynamic #99 // malformed",
            "12: putstatic #30 // Field fixture/Target.VALUE:I",
            "13: putstatic #31 // Field fixture/Target.VALUE:Ljava.lang.Bad;",
            "14: new #32 // class fixture/NewType",
            "15: new #33 // class bad name",
        )
        reference_set = FinalArtifactBootstrapBoundaryTest.reference_set(
            types=(("type", "java/lang/Integer"),),
        )
        with patch.object(
            oracle, "_bootstrap_references", return_value={0: reference_set},
        ):
            structural = oracle.parse_structural_javap(output)
        failures = structural["failures"]
        self.assertTrue(any("MethodType" in item for item in failures))
        self.assertTrue(any("ConstantDynamic" in item for item in failures))
        self.assertTrue(any("MethodHandle" in item for item in failures))
        self.assertTrue(any("class reference" in item for item in failures))
        self.assertTrue(any("invokedynamic" in item for item in failures))
        self.assertTrue(any("putstatic" in item for item in failures))
        self.assertTrue(structural["type_edges"])
        self.assertTrue(structural["class_init_edges"])

        with patch.object(
            oracle, "_constant_dynamic_references",
            return_value={22: (0, "value", "I")},
        ), patch.object(
            oracle, "_bootstrap_references", return_value={0: reference_set},
        ):
            known = oracle.parse_structural_javap(self.wrapper(
                "0: ldc #22 // not-a-Dynamic-comment",
                "1: ldc // Dynamic #0:value:I",
            ))
        self.assertTrue(known["type_edges"])

    def test_structural_references_without_constant_pool_indexes(self):
        reference_set = FinalArtifactBootstrapBoundaryTest.reference_set()
        with patch.object(
            oracle, "_bootstrap_references", return_value={0: reference_set},
        ):
            constant_dynamic = oracle.parse_structural_javap(self.wrapper(
                "0: ldc // Dynamic #0:value:Ljava/util/Map;",
            ))
        self.assertIn(
            (
                "fixture/Caller", "call", "()V", 0,
                "java/util/Map", "constant_dynamic_descriptor",
            ),
            constant_dynamic["type_edges"],
        )

        malformed_constant_dynamic = oracle.parse_structural_javap(self.wrapper(
            "0: ldc // Dynamic malformed",
        ))
        self.assertTrue(any(
            "unresolved ConstantDynamic type arguments at 0" in failure
            for failure in malformed_constant_dynamic["failures"]
        ))

        ordinary_constant = oracle.parse_structural_javap(self.wrapper(
            "0: ldc #77 // string literal",
        ))
        self.assertFalse(any(
            "class reference at 0" in failure
            for failure in ordinary_constant["failures"]
        ))

        with patch.object(
            oracle, "_bootstrap_references", return_value={0: reference_set},
        ):
            invokedynamic = oracle.parse_structural_javap(self.wrapper(
                "0: invokedynamic // InvokeDynamic #0:run:()Ljava/util/List;",
            ))
        self.assertIn(
            (
                "fixture/Caller", "call", "()V", 0,
                "java/util/List", "invokedynamic_callsite_descriptor",
            ),
            invokedynamic["type_edges"],
        )

        malformed_invokedynamic = oracle.parse_structural_javap(self.wrapper(
            "0: invokedynamic // malformed",
        ))
        self.assertTrue(any(
            "unresolved invokedynamic type arguments at 0" in failure
            for failure in malformed_invokedynamic["failures"]
        ))

    def test_structural_raw_method_type_constant_cross_check_matrix(self):
        inventory = self.inventory(
            (self.method(),),
            method_types=((20, "(I)V"), (21, "()V")),
        )
        output = "\n".join((
            "public class fixture.Caller {",
            "  public void call();",
            "    descriptor: ()V",
            "    Code:",
            "       0: ldc #20 // MethodType (J)V",
            "       1: ldc #21 // not-a-method-type",
            "}",
        ))
        structural = oracle.parse_structural_javap(output, inventory)
        failures = structural["failures"]
        self.assertTrue(any("lossy or unparseable ldc MethodType" in item for item in failures))

    def test_structural_clinit_and_access_flag_declarations(self):
        output = "\n".join((
            "public class fixture.Caller {",
            "  static {};",
            "    Code:",
            "       0: return",
            "  public private protected static final abstract void call();",
            "    descriptor: ()V",
            "  public static final int VALUE;",
            "    descriptor: I",
            "}",
        ))
        structural = oracle.parse_structural_javap(output)
        self.assertIn("fixture/Caller", structural["clinit_classes"])
        self.assertEqual(len(structural["declared_members"]), 3)


class FinalArtifactProcessAndExtractionBoundaryTest(unittest.TestCase):
    CLASS_BYTES = _minimal_inventory_class()

    def test_small_process_and_path_helpers_cover_success_failure_and_windows_codes(self):
        with patch.object(
            oracle,
            "run_managed_subprocess",
            return_value=SimpleNamespace(stdout="javap 21", stderr="fallback"),
        ):
            self.assertEqual(oracle._javap_version("javap", timeout=1), "javap 21")
        with patch.object(
            oracle,
            "run_managed_subprocess",
            return_value=SimpleNamespace(stdout="", stderr="javap 17"),
        ):
            self.assertEqual(oracle._javap_version("javap", timeout=1), "javap 17")
        self.assertEqual(oracle._javap_major("javap 1.8.0"), 8)
        self.assertEqual(oracle._javap_major("no-version"), None)

        e2big = OSError(errno.E2BIG, "too long")
        windows = OSError("too long")
        windows.winerror = 206
        ordinary = OSError(errno.ENOENT, "missing")
        self.assertTrue(oracle._command_line_too_long(e2big))
        self.assertTrue(oracle._command_line_too_long(windows))
        self.assertFalse(oracle._command_line_too_long(ordinary))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "new.class"
            content_entry = oracle.PackagedClass("A.class", missing, b"abc")
            self.assertEqual(oracle._materialize_packaged_class(content_entry), "")
            self.assertEqual(missing.read_bytes(), b"abc")
            self.assertEqual(oracle._materialize_packaged_class(content_entry), "")
            self.assertEqual(
                oracle._materialize_packaged_class(
                    oracle.PackagedClass("B.class", root / "b.class", None),
                ),
                "",
            )
            self.assertEqual(
                oracle._materialize_packaged_class(
                    oracle.PackagedClass(
                        "C.class", root / "c.class", b"x", javap_argument="jar:file:x",
                    ),
                ),
                "",
            )
            with patch.object(Path, "write_bytes", side_effect=OSError("denied")):
                self.assertIn(
                    "denied",
                    oracle._materialize_packaged_class(
                        oracle.PackagedClass("D.class", root / "d.class", b"x"),
                    ),
                )

        entry = oracle.PackagedClass("A.class", Path("a.class"), b"x")
        self.assertEqual(oracle._javap_batch_groups([], 1, "javap"), [])
        with patch.object(oracle, "_javap_batch_command_chars", return_value=100):
            with patch.object(oracle, "MAX_JAVAP_COMMAND_CHARS", 50):
                groups = oracle._javap_batch_groups([entry, entry], 1, "javap")
        self.assertEqual([len(group) for group in groups], [1, 1])

    def test_stage_javap_archive_accepts_bytes_and_rejects_missing_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged = oracle._stage_javap_archive(
                root,
                [oracle.PackagedClass("A.class", root / "a.class", b"abc")],
            )
            self.assertEqual(len(staged), 1)
            self.assertTrue(staged[0].javap_argument.startswith("jar:file:"))
            with zipfile.ZipFile(root / "javap-classes.jar") as archive:
                self.assertEqual(archive.read("classes/class-000000.class"), b"abc")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                oracle._stage_javap_archive(
                    root,
                    [oracle.PackagedClass("Missing.class", root / "missing.class")],
                )

    def test_cancel_process_is_idempotent_across_cleanup_failures_and_timeout_pipes(self):
        normal = Mock()
        normal.communicate.return_value = ("", "")
        with patch.object(oracle, "terminate_process_tree"), patch.object(
            oracle, "release_process_tree",
        ) as release:
            oracle._cancel_process(normal)
            release.assert_called_once_with(normal)

        for error in (OSError("closed"), ValueError("closed")):
            process = Mock()
            process.communicate.side_effect = error
            with patch.object(
                oracle, "terminate_process_tree", side_effect=RuntimeError("raced"),
            ), patch.object(oracle, "release_process_tree"):
                oracle._cancel_process(process)

        good_pipe = Mock()
        bad_pipe = Mock()
        bad_pipe.close.side_effect = OSError("already closed")
        process = Mock(stdin=None, stdout=good_pipe, stderr=bad_pipe)
        process.communicate.side_effect = subprocess.TimeoutExpired("javap", 5)
        with patch.object(oracle, "terminate_process_tree"), patch.object(
            oracle, "release_process_tree",
        ):
            oracle._cancel_process(process)
        good_pipe.close.assert_called_once_with()
        bad_pipe.close.assert_called_once_with()

    def test_extract_classes_supports_bytes_paths_streams_boot_layout_and_write_modes(self):
        boot_archive = _zip_bytes((
            ("Root.class", self.CLASS_BYTES),
            ("BOOT-INF/classes/", b""),
            ("BOOT-INF/classes/App.class", self.CLASS_BYTES),
        ))
        plain_archive = _zip_bytes((("Root.class", self.CLASS_BYTES),))
        boot_directory_only = _zip_bytes((
            ("BOOT-INF/classes/", b""),
            ("Root.class", self.CLASS_BYTES),
        ))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(oracle, "_classfile_header_facts", return_value=(False, 0)):
                entries, failures = oracle._extract_packaged_classes(
                    boot_archive,
                    root,
                    21,
                    defer_writes=True,
                    include_nested_runtime_jars=False,
                )
            self.assertEqual([entry.artifact_entry for entry in entries], ["BOOT-INF/classes/App.class"])
            self.assertIsNotNone(entries[0].content)
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(oracle, "_classfile_header_facts", return_value=(False, 0)):
                entries, failures = oracle._extract_packaged_classes(
                    boot_directory_only,
                    root,
                    21,
                    defer_writes=True,
                    include_nested_runtime_jars=False,
                )
            self.assertEqual([entry.artifact_entry for entry in entries], ["Root.class"])
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "plain.jar"
            artifact.write_bytes(plain_archive)
            with patch.object(oracle, "_classfile_header_facts", return_value=(False, 0)):
                entries, failures = oracle._extract_packaged_classes(
                    artifact, root, 21, include_nested_runtime_jars=False,
                )
            self.assertEqual(failures, [])
            self.assertIsNone(entries[0].content)
            self.assertTrue(entries[0].extracted_path.exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stream = io.BytesIO(plain_archive)
            stream.seek(len(plain_archive))
            with patch.object(oracle, "_classfile_header_facts", return_value=(False, 0)):
                entries, failures = oracle._extract_packaged_classes(
                    stream,
                    root,
                    21,
                    defer_writes=True,
                    include_nested_runtime_jars=False,
                )
            self.assertEqual(len(entries), 1)
            self.assertEqual(failures, [])

    def test_extract_classes_handles_manifest_module_nested_and_staging_failures(self):
        plain_archive = _zip_bytes((("Root.class", self.CLASS_BYTES),))
        nested_archive = _zip_bytes((("Nested.class", self.CLASS_BYTES),))
        outer_with_nested = _zip_bytes((
            ("BOOT-INF/lib/nested.jar", nested_archive),
        ))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                oracle, "_classfile_header_facts", return_value=(False, None),
            ):
                entries, failures = oracle._extract_packaged_classes(
                    plain_archive, root, 21, defer_writes=True,
                    include_nested_runtime_jars=False,
                )
            self.assertEqual(len(entries), 1)
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                oracle, "_multi_release_manifest_failures", return_value=["ambiguous"],
            ):
                entries, failures = oracle._extract_packaged_classes(
                    plain_archive, root, 21, include_nested_runtime_jars=False,
                )
            self.assertEqual(entries, [])
            self.assertEqual(failures, ["ambiguous"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                oracle, "_classfile_header_facts", return_value=(False, oracle.ACC_MODULE),
            ), patch.object(
                oracle, "_classfile_is_valid_module_descriptor", return_value=True,
            ):
                entries, failures = oracle._extract_packaged_classes(
                    plain_archive, root, 21, include_nested_runtime_jars=False,
                )
            self.assertEqual(entries, [])
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                oracle, "_classfile_header_facts", return_value=(False, oracle.ACC_MODULE),
            ), patch.object(
                oracle, "_classfile_is_valid_module_descriptor", return_value=False,
            ):
                entries, failures = oracle._extract_packaged_classes(
                    plain_archive, root, 21, defer_writes=True,
                    include_nested_runtime_jars=False,
                )
            self.assertEqual([entry.artifact_entry for entry in entries], ["Root.class"])
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                oracle, "_classfile_header_facts", return_value=(False, oracle.ACC_MODULE),
            ), patch.object(
                oracle, "_classfile_is_valid_module_descriptor", return_value=False,
            ):
                entries, failures = oracle._extract_packaged_classes(
                    outer_with_nested, root, 21, defer_writes=True,
                )
            self.assertEqual([entry.artifact_entry for entry in entries], ["BOOT-INF/lib/nested.jar!/Nested.class"])
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                oracle, "_classfile_header_facts", return_value=(False, oracle.ACC_MODULE),
            ), patch.object(
                oracle, "_classfile_is_valid_module_descriptor", return_value=True,
            ):
                entries, failures = oracle._extract_packaged_classes(
                    outer_with_nested, root, 21, defer_writes=True,
                )
            self.assertEqual(entries, [])
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(oracle, "_classfile_header_facts", return_value=(False, 0)):
                entries, failures = oracle._extract_packaged_classes(
                    outer_with_nested,
                    root,
                    21,
                    excluded_nested_jars={"BOOT-INF/lib/nested.jar"},
                )
            self.assertEqual(entries, [])
            self.assertEqual(failures, [])

        duplicate_nested = _zip_bytes((
            ("BOOT-INF/lib/nested.jar", nested_archive),
            ("BOOT-INF/lib/nested.jar", nested_archive),
        ))
        bad_nested = _zip_bytes((("BOOT-INF/lib/bad.jar", b"not-a-jar"),))
        nested_directory = _zip_bytes((("BOOT-INF/lib/", b""),))
        with tempfile.TemporaryDirectory() as temporary:
            entries, failures = oracle._extract_packaged_classes(
                nested_directory, Path(temporary), 21,
            )
        self.assertEqual(entries, [])
        self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(
                oracle,
                "_multi_release_manifest_failures",
                side_effect=([], ["nested ambiguous"]),
            ):
                entries, failures = oracle._extract_packaged_classes(
                    outer_with_nested, Path(temporary), 21,
                )
        self.assertEqual(entries, [])
        self.assertIn("nested ambiguous", failures)
        for archive_bytes, fragment in (
            (duplicate_nested, "duplicate nested JAR"),
            (bad_nested, "nested JAR read failed"),
        ):
            with tempfile.TemporaryDirectory() as temporary:
                entries, failures = oracle._extract_packaged_classes(
                    archive_bytes, Path(temporary), 21,
                )
            self.assertEqual(entries, [])
            self.assertTrue(any(fragment in failure for failure in failures))

        two_classes = _zip_bytes((
            ("A.class", self.CLASS_BYTES),
            ("B.class", self.CLASS_BYTES),
        ))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(oracle, "_classfile_header_facts", return_value=(False, 0)):
                entries, failures = oracle._extract_packaged_classes(
                    two_classes,
                    root,
                    21,
                    stage_javap_archive=True,
                    max_staged_class_bytes=len(self.CLASS_BYTES),
                )
            self.assertEqual(len(entries), 2)
            self.assertTrue(all(entry.content is None for entry in entries))
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                oracle, "_classfile_header_facts", return_value=(False, 0)
            ):
                entries, failures = oracle._extract_packaged_classes(
                    plain_archive,
                    root,
                    21,
                    defer_writes=True,
                    retain_class_bytes=True,
                )
            self.assertEqual(entries[0].content, self.CLASS_BYTES)
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                oracle, "_classfile_header_facts", return_value=(False, 0)
            ):
                entries, failures = oracle._extract_packaged_classes(
                    two_classes,
                    root,
                    21,
                    retain_class_bytes=True,
                    max_staged_class_bytes=len(self.CLASS_BYTES),
                )
            self.assertEqual(len(entries), 2)
            self.assertTrue(all(entry.content is None for entry in entries))
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(oracle, "_classfile_header_facts", return_value=(False, 0)), patch.object(
                oracle, "_stage_javap_archive", side_effect=OSError("staging failed"),
            ):
                entries, failures = oracle._extract_packaged_classes(
                    plain_archive, root, 21, stage_javap_archive=True,
                )
            self.assertEqual(len(entries), 1)
            self.assertIsNone(entries[0].content)
            self.assertEqual(failures, [])

        with tempfile.TemporaryDirectory() as temporary:
            entries, failures = oracle._extract_packaged_classes(
                _zip_bytes(()),
                Path(temporary),
                21,
                stage_javap_archive=True,
            )
            self.assertEqual(entries, [])
            self.assertEqual(failures, [])

    def test_scan_reports_archive_inspection_cancellation(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.jar"
            artifact.write_bytes(_zip_bytes(()))
            safety = SimpleNamespace(
                safe=False, reason_codes=("ARCHIVE_INSPECTION_CANCELLED",),
            )
            with patch.object(oracle, "inspect_archive_stream", return_value=safety):
                result = oracle.scan_final_artifact(
                    artifact, time_budget_seconds=1,
                )
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["complete"])
        self.assertTrue(any("time_budget" in item for item in result["failures"]))


class FinalArtifactJavapExecutionBoundaryTest(unittest.TestCase):
    @staticmethod
    def entry(root: Path, name: str = "A.class", **values):
        return oracle.PackagedClass(
            name,
            root / name.replace("/", "-"),
            values.pop("content", _minimal_inventory_class()),
            **values,
        )

    @staticmethod
    def process(*, returncode=0, stdout="output", stderr=""):
        process = Mock(returncode=returncode, stdin=None, stdout=None, stderr=None)
        process.communicate.return_value = (stdout, stderr)
        return process

    def test_windows_path_binding_and_transient_spawn_retry(self):
        with patch.object(oracle.os, "name", "nt"):
            self.assertEqual(
                oracle._javap_path_key(r"C:\work\classes\A.class"),
                oracle._javap_path_key("/C:/work/classes/A.class"),
            )
            self.assertNotEqual(
                oracle._javap_path_key(
                    "jar:file:///C:/work/app.jar!/classes/A.class"
                ),
                oracle._javap_path_key(
                    "jar:file:///C:/work/app.jar!/classes/a.class"
                ),
            )
            self.assertEqual(
                oracle._javap_path_key("jar:file:///C:/work/app.jar"),
                "jar:file:///c:/work/app.jar",
            )

        transient = OSError(errno.EACCES, "temporarily denied")
        transient.winerror = 5
        process = self.process()
        cancellation = Mock()
        cancellation.is_set.return_value = False
        cancellation.wait.return_value = False
        with patch.object(
            oracle, "managed_popen", side_effect=(transient, process),
        ) as popen, patch.object(
            oracle.time, "perf_counter", return_value=0,
        ):
            started = oracle._spawn_javap(
                ["javap", "A.class"], cancellation, 10,
            )

        self.assertIs(started, process)
        self.assertEqual(popen.call_count, 2)
        cancellation.wait.assert_called_once()

    def test_spawn_retry_exhaustion_cancellation_deadline_and_empty_attempts(self):
        transient = OSError(errno.EAGAIN, "retry")
        cancellation = Mock()
        cancellation.is_set.side_effect = (False, True)
        with patch.object(
            oracle, "managed_popen", side_effect=transient,
        ), patch.object(oracle.time, "perf_counter", return_value=0):
            with self.assertRaises(OSError):
                oracle._spawn_javap(["javap"], cancellation, 10)

        cancellation = Mock()
        cancellation.is_set.return_value = False
        cancellation.wait.return_value = False
        with patch.object(
            oracle, "managed_popen", side_effect=transient,
        ), patch.object(
            oracle.time, "perf_counter", return_value=10,
        ):
            with self.assertRaises(OSError):
                oracle._spawn_javap(["javap"], cancellation, 1)

        cancellation = Mock()
        cancellation.is_set.return_value = False
        with patch.object(oracle, "JAVAP_SPAWN_MAX_ATTEMPTS", 0):
            with self.assertRaisesRegex(TimeoutError, "deadline exceeded"):
                oracle._spawn_javap(["javap"], cancellation, 1)

        cancellation = Mock()
        cancellation.is_set.return_value = False
        cancellation.wait.return_value = False
        with patch.object(
            oracle, "managed_popen", side_effect=transient,
        ), patch.object(oracle.time, "perf_counter", return_value=0):
            with self.assertRaises(OSError):
                oracle._spawn_javap(["javap"], cancellation, 10)

    def test_persistent_single_and_group_javap_transport_boundaries(self):
        from javap_session import JavapSessionResult

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self.entry(root, "A.class", requires_verbose_javap=False)
            second = self.entry(root, "B.class", requires_verbose_javap=False)
            failed = JavapSessionResult(1, "stdout", "stderr")
            with patch.object(
                oracle, "run_persistent_javap", return_value=failed,
            ) as persistent, patch.object(
                oracle, "_spawn_javap",
                side_effect=AssertionError("one-shot fallback was not expected"),
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                result = oracle._parse_entry_with_javap(
                    first, "sha", "javap", "21", Event(), 100,
                    persistent_javap_sessions=True,
                )
            self.assertIn("javap failed: stderr", result["failures"][0])
            persistent.assert_called_once()

            changing = Mock()
            changing.is_set.side_effect = (False, True)
            with patch.object(
                oracle, "run_persistent_javap", return_value=None,
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                result = oracle._parse_entry_with_javap(
                    first, "sha", "javap", "21", changing, 100,
                    persistent_javap_sessions=True,
                )
            self.assertFalse(result["completed"])

            with patch.object(
                oracle, "run_persistent_javap", return_value=None,
            ), patch.object(
                oracle, "_spawn_javap", return_value=self.process(returncode=1),
            ) as spawn, patch.object(
                oracle, "release_process_tree",
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                result = oracle._parse_entry_with_javap(
                    first, "sha", "javap", "21", Event(), 100,
                    persistent_javap_sessions=True,
                )
            self.assertFalse(result["parsed"])
            spawn.assert_called_once()

            event = Mock()
            event.is_set.return_value = False
            with patch.object(
                oracle, "run_persistent_javap", return_value=None,
            ), patch.object(
                oracle.time, "perf_counter", side_effect=(0, 0, 101),
            ):
                result = oracle._parse_entry_with_javap(
                    first, "sha", "javap", "21", event, 100,
                    persistent_javap_sessions=True,
                )
            self.assertFalse(result["completed"])

            fallback = {
                "rows": [], "failures": [], "completed": True, "parsed": True,
            }
            with patch.object(
                oracle, "run_persistent_javap", return_value=failed,
            ), patch.object(
                oracle, "_parse_entry_with_javap", return_value=fallback,
            ) as separate, patch.object(
                oracle.time, "perf_counter", return_value=0,
            ):
                results = oracle._parse_entry_group_with_javap(
                    [first, second], "sha", "javap", "21", Event(), 100,
                    force_verbose=False, persistent_javap_sessions=True,
                )
            self.assertEqual(len(results), 2)
            self.assertEqual(separate.call_count, 2)

            changing = Mock()
            changing.is_set.side_effect = (False, True)
            with patch.object(
                oracle, "run_persistent_javap", return_value=None,
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                results = oracle._parse_entry_group_with_javap(
                    [first, second], "sha", "javap", "21", changing, 100,
                    force_verbose=False, persistent_javap_sessions=True,
                )
            self.assertTrue(all(not result["completed"] for result in results))

            event = Mock()
            event.is_set.return_value = False
            with patch.object(
                oracle, "run_persistent_javap", return_value=None,
            ), patch.object(
                oracle.time, "perf_counter", side_effect=(0, 0, 101),
            ):
                results = oracle._parse_entry_group_with_javap(
                    [first, second], "sha", "javap", "21", event, 100,
                    force_verbose=False, persistent_javap_sessions=True,
                )
            self.assertTrue(all(not result["completed"] for result in results))

            with patch.object(
                oracle, "run_persistent_javap", return_value=None,
            ), patch.object(
                oracle, "_spawn_javap", return_value=self.process(returncode=1),
            ) as spawn, patch.object(
                oracle, "release_process_tree",
            ), patch.object(
                oracle, "_parse_entry_with_javap", return_value=fallback,
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                results = oracle._parse_entry_group_with_javap(
                    [first, second], "sha", "javap", "21", Event(), 100,
                    force_verbose=False, persistent_javap_sessions=True,
                )
            self.assertEqual(len(results), 2)
            spawn.assert_called_once()

            success = JavapSessionResult(
                0,
                f"Classfile {first.extracted_path}\nfirst\n"
                f"Classfile {second.extracted_path}\nsecond\n",
                "",
            )
            inventory = FinalArtifactParserBoundaryTest.inventory()
            inventory_future = Mock()
            inventory_future.result.return_value = ((inventory, None),)
            with patch.object(
                oracle, "run_persistent_javap", return_value=success,
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                with self.assertRaisesRegex(RuntimeError, "conservation mismatch"):
                    oracle._parse_entry_group_with_javap_impl(
                        [first, second], "sha", "javap", "21", Event(), 100,
                        force_verbose=False,
                        persistent_javap_sessions=True,
                        inventory_future=inventory_future,
                    )

            for error in (
                TimeoutError("timeout"),
                OSError(errno.EAGAIN, "retryable"),
            ):
                with self.subTest(error=type(error).__name__), patch.object(
                    oracle, "_spawn_javap", side_effect=error,
                ), patch.object(
                    oracle, "_parse_entry_with_javap", return_value=fallback,
                ), patch.object(oracle.time, "perf_counter", return_value=0):
                    results = oracle._parse_entry_group_with_javap(
                        [first, second], "sha", "javap", "21", Event(), 100,
                        force_verbose=False,
                    )
                self.assertEqual(len(results), 2)

            with patch.object(
                oracle, "_parse_entry_group_with_javap",
                return_value=[fallback],
            ) as parse_group:
                results, submitted, timed_out, interrupted = oracle._parse_entry_batch(
                    [first], "sha", "javap", "21", Event(), None, 1,
                    persistent_javap_sessions=True,
                )
            self.assertEqual(submitted, 1)
            self.assertFalse(timed_out)
            self.assertFalse(interrupted)
            self.assertTrue(results[0]["parsed"])
            self.assertTrue(
                parse_group.call_args.kwargs["persistent_javap_sessions"]
            )

    def test_single_entry_javap_preflight_execution_and_result_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = self.entry(root)
            with patch.object(
                oracle, "_materialize_packaged_class", return_value="denied",
            ):
                result = oracle._parse_entry_with_javap(
                    entry, "sha", "javap", "21", Event(), None,
                )
            self.assertIn("materialization failed", result["failures"][0])

            cancelled = Event()
            cancelled.set()
            result = oracle._parse_entry_with_javap(
                entry, "sha", "javap", "21", cancelled, None,
            )
            self.assertFalse(result["completed"])
            with patch.object(oracle.time, "perf_counter", return_value=10):
                result = oracle._parse_entry_with_javap(
                    entry, "sha", "javap", "21", Event(), 5,
                )
            self.assertFalse(result["completed"])

            for verbose in (True, False, None):
                process = self.process(returncode=1, stdout="stdout", stderr="stderr")
                with patch.object(oracle, "managed_popen", return_value=process) as popen, patch.object(
                    oracle, "release_process_tree",
                ), patch.object(oracle.time, "perf_counter", return_value=0), patch.object(
                    oracle, "_entry_requires_verbose_javap", return_value=True,
                ):
                    result = oracle._parse_entry_with_javap(
                        entry, "sha", "javap", "21", Event(), 100,
                        verbose=verbose,
                    )
                command = popen.call_args.args[0]
                self.assertEqual("-v" in command, verbose is not False)
                self.assertIn("javap failed: stderr", result["failures"][0])

            with patch.object(oracle, "managed_popen", side_effect=OSError("missing")), patch.object(
                oracle.time, "perf_counter", return_value=0,
            ):
                result = oracle._parse_entry_with_javap(
                    entry, "sha", "javap", "21", Event(), 100,
                )
            self.assertIn("execution failed", result["failures"][0])

            process = self.process(returncode=1, stdout="stdout", stderr="")
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "release_process_tree",
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                result = oracle._parse_entry_with_javap(
                    entry, "sha", "javap", "21", Event(), 100,
                )
            self.assertIn("javap failed: stdout", result["failures"][0])

            process = self.process()
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "release_process_tree",
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                result = oracle._parse_entry_with_javap(
                    entry, "sha", "javap", "", Event(), 100,
                )
            self.assertIn("version was empty", result["failures"][0])

    def test_single_entry_javap_timeout_exception_inventory_and_success_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = self.entry(root)
            process = self.process()
            process.communicate.side_effect = [
                subprocess.TimeoutExpired("javap", 0.1),
                ("output", ""),
            ]
            inventory = FinalArtifactParserBoundaryTest.inventory(
                (FinalArtifactParserBoundaryTest.method(),),
            )
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "release_process_tree",
            ), patch.object(oracle.time, "perf_counter", return_value=0), patch.object(
                oracle, "_entry_member_inventory", return_value=(inventory, None),
            ), patch.object(
                oracle, "_parse_javap_output", return_value=([{"edge": 1}], []),
            ), patch.object(
                oracle,
                "parse_structural_javap",
                return_value={"failures": {"structural failure"}, "type_edges": set()},
            ):
                result = oracle._parse_entry_with_javap(
                    entry, "sha", "javap", "21", Event(), 100,
                )
            self.assertTrue(result["parsed"])
            self.assertEqual(result["rows"], [{"edge": 1}])
            self.assertIn("structural failure", result["failures"][0])

            for inventory_result, fragment in (
                ((None, "bad inventory"), "bad inventory"),
                ((None, None), "unavailable"),
            ):
                process = self.process()
                with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                    oracle, "release_process_tree",
                ), patch.object(oracle.time, "perf_counter", return_value=0), patch.object(
                    oracle, "_entry_member_inventory", return_value=inventory_result,
                ):
                    result = oracle._parse_entry_with_javap(
                        entry, "sha", "javap", "21", Event(), 100,
                    )
                self.assertIn(fragment, result["failures"][0])

            process = self.process()
            process.communicate.side_effect = RuntimeError("pipe failed")
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "_cancel_process",
            ) as cancel, patch.object(oracle.time, "perf_counter", return_value=0):
                with self.assertRaisesRegex(RuntimeError, "pipe failed"):
                    oracle._parse_entry_with_javap(
                        entry, "sha", "javap", "21", Event(), 100,
                    )
            cancel.assert_called_once_with(process)

            process = self.process()
            event = Event()
            perf_values = iter((0, 0, 301))
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "_cancel_process",
            ) as cancel, patch.object(
                oracle.time, "perf_counter", side_effect=lambda: next(perf_values),
            ):
                result = oracle._parse_entry_with_javap(
                    entry, "sha", "javap", "21", event, 1000,
                )
            self.assertFalse(result["completed"])
            cancel.assert_called_once_with(process)

            process = self.process()
            changing_event = Mock()
            changing_event.is_set.side_effect = (False, True)
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "_cancel_process",
            ) as cancel, patch.object(oracle.time, "perf_counter", return_value=0):
                result = oracle._parse_entry_with_javap(
                    entry, "sha", "javap", "21", changing_event, 100,
                )
            self.assertFalse(result["completed"])
            cancel.assert_called_once_with(process)

    def test_group_dispatch_split_preflight_and_command_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plain = self.entry(root, "Plain.class", requires_verbose_javap=False)
            verbose = self.entry(root, "Verbose.class", requires_verbose_javap=True)
            self.assertEqual(
                oracle._parse_entry_group_with_javap(
                    [], "sha", "javap", "21", Event(), None,
                ),
                [],
            )
            with patch.object(
                oracle,
                "_parse_entry_with_javap",
                side_effect=lambda entry, *_args, **_kwargs: {
                    "rows": [entry.artifact_entry], "failures": [],
                    "completed": True, "parsed": True,
                },
            ):
                results = oracle._parse_entry_group_with_javap(
                    [plain, verbose], "sha", "javap", "21", Event(), None,
                )
            self.assertEqual(
                [result["rows"][0] for result in results],
                ["Plain.class", "Verbose.class"],
            )

            with patch.object(
                oracle, "_materialize_packaged_class",
                side_effect=("denied", ""),
            ), patch.object(
                oracle, "_parse_entry_with_javap",
                return_value={"rows": [], "failures": [], "completed": True, "parsed": False},
            ) as separate:
                oracle._parse_entry_group_with_javap(
                    [plain, verbose], "sha", "javap", "21", Event(), None,
                    force_verbose=False,
                )
            self.assertEqual(separate.call_count, 2)

            cancelled = Event()
            cancelled.set()
            results = oracle._parse_entry_group_with_javap(
                [plain, verbose], "sha", "javap", "21", cancelled, None,
                force_verbose=True,
            )
            self.assertTrue(all(not result["completed"] for result in results))

            perf_values = iter((0, 301))
            with patch.object(
                oracle.time, "perf_counter", side_effect=lambda: next(perf_values),
            ):
                results = oracle._parse_entry_group_with_javap(
                    [plain, verbose], "sha", "javap", "21", Event(), None,
                    force_verbose=True,
                )
            self.assertTrue(all(not result["completed"] for result in results))

            ordinary_error = OSError(errno.ENOENT, "missing")
            with patch.object(oracle, "managed_popen", side_effect=ordinary_error), patch.object(
                oracle.time, "perf_counter", return_value=0,
            ):
                results = oracle._parse_entry_group_with_javap(
                    [plain, verbose], "sha", "javap", "21", Event(), 100,
                    force_verbose=False,
                )
            self.assertTrue(all("execution failed" in result["failures"][0] for result in results))

            with patch.object(
                oracle, "managed_popen", side_effect=OSError(errno.E2BIG, "long"),
            ), patch.object(
                oracle, "_parse_entry_with_javap",
                return_value={"rows": [], "failures": [], "completed": True, "parsed": True},
            ) as separate, patch.object(oracle.time, "perf_counter", return_value=0):
                results = oracle._parse_entry_group_with_javap(
                    [plain, verbose], "sha", "javap", "21", Event(), 100,
                    force_verbose=True,
                )
            self.assertEqual(len(results), 2)
            self.assertEqual(separate.call_count, 2)

    def test_group_timeout_nonzero_sections_and_inventory_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self.entry(root, "A.class", requires_verbose_javap=False)
            second = self.entry(root, "B.class", requires_verbose_javap=False)
            entries = [first, second]
            fallback = {"rows": [], "failures": [], "completed": True, "parsed": True}

            process = self.process()
            perf_values = iter((0, 0, 301, 301))
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "_cancel_process",
            ), patch.object(
                oracle, "_parse_entry_with_javap", return_value=fallback,
            ) as separate, patch.object(
                oracle.time, "perf_counter", side_effect=lambda: next(perf_values),
            ):
                results = oracle._parse_entry_group_with_javap(
                    entries, "sha", "javap", "21", Event(), 1000,
                    force_verbose=False,
                )
            self.assertEqual(len(results), 2)
            self.assertEqual(separate.call_count, 2)

            process = self.process()
            perf_values = iter((0, 0, 301))
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "_cancel_process",
            ), patch.object(
                oracle, "_parse_entry_with_javap", return_value=fallback,
            ) as separate, patch.object(
                oracle.time, "perf_counter", side_effect=lambda: next(perf_values),
            ):
                results = oracle._parse_entry_group_with_javap(
                    entries, "sha", "javap", "21", Event(), None,
                    force_verbose=False,
                )
            self.assertEqual(len(results), 2)
            self.assertEqual(separate.call_count, 2)

            process = self.process()
            changing_event = Mock()
            changing_event.is_set.side_effect = (False, True, True)
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "_cancel_process",
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                results = oracle._parse_entry_group_with_javap(
                    entries, "sha", "javap", "21", changing_event, None,
                    force_verbose=False,
                )
            self.assertTrue(all(not result["completed"] for result in results))

            process = self.process()
            perf_values = iter((0, 0, 2, 2))
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "_cancel_process",
            ), patch.object(
                oracle.time, "perf_counter", side_effect=lambda: next(perf_values),
            ):
                results = oracle._parse_entry_group_with_javap(
                    entries, "sha", "javap", "21", Event(), 1,
                    force_verbose=False,
                )
            self.assertTrue(all(not result["completed"] for result in results))

            process = self.process(returncode=1)
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "release_process_tree",
            ), patch.object(
                oracle, "_parse_entry_with_javap", return_value=fallback,
            ) as separate, patch.object(oracle.time, "perf_counter", return_value=0):
                results = oracle._parse_entry_group_with_javap(
                    entries, "sha", "javap", "21", Event(), 100,
                    force_verbose=True,
                )
            self.assertEqual(len(results), 2)
            self.assertEqual(separate.call_count, 2)

            section = f"Classfile {first.extracted_path}\npublic class A {{}}\n"
            process = self.process(stdout=section)
            inventory = FinalArtifactParserBoundaryTest.inventory()
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "release_process_tree",
            ), patch.object(oracle.time, "perf_counter", return_value=0), patch.object(
                oracle, "_entry_member_inventory",
                side_effect=((inventory, None), (None, "bad inventory")),
            ), patch.object(
                oracle, "_parse_javap_output", return_value=([], []),
            ), patch.object(
                oracle, "parse_structural_javap", return_value={"failures": set()},
            ), patch.object(
                oracle, "_parse_entry_with_javap", return_value=fallback,
            ) as separate:
                results = oracle._parse_entry_group_with_javap(
                    entries, "sha", "javap", "21", Event(), 100,
                    force_verbose=False,
                )
            self.assertTrue(results[0]["parsed"])
            self.assertTrue(results[1]["parsed"])
            separate.assert_called_once()

            stdout = (
                f"Classfile {first.extracted_path}\nfirst\n"
                f"Classfile {second.extracted_path}\nsecond\n"
            )
            process = self.process(stdout=stdout)
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "release_process_tree",
            ), patch.object(oracle.time, "perf_counter", return_value=0), patch.object(
                oracle, "_entry_member_inventory",
                side_effect=((inventory, None), (None, None)),
            ), patch.object(
                oracle, "_parse_javap_output", return_value=([], []),
            ), patch.object(
                oracle, "parse_structural_javap", return_value={"failures": {"structural"}},
            ):
                results = oracle._parse_entry_group_with_javap(
                    entries, "sha", "javap", "21", Event(), 100,
                    force_verbose=False,
                )
            self.assertTrue(results[0]["parsed"])
            self.assertFalse(results[1]["parsed"])
            self.assertIn("unavailable", results[1]["failures"][0])

            process = self.process(stdout=stdout)
            with patch.object(oracle, "managed_popen", return_value=process), patch.object(
                oracle, "release_process_tree",
            ), patch.object(oracle.time, "perf_counter", return_value=0), patch.object(
                oracle, "_entry_member_inventory",
                side_effect=((inventory, None), (None, "bad inventory")),
            ), patch.object(
                oracle, "_parse_javap_output", return_value=([], []),
            ), patch.object(
                oracle, "parse_structural_javap", return_value={"failures": set()},
            ):
                results = oracle._parse_entry_group_with_javap(
                    entries, "sha", "javap", "21", Event(), 100,
                    force_verbose=False,
                )
            self.assertIn("bad inventory", results[1]["failures"][0])

    def test_entry_batch_executor_deadline_cancel_exception_and_interrupt_matrix(self):
        class FakeExecutor:
            def __init__(self, futures=(), submit_error=None):
                self.pending = list(futures)
                self.submit_error = submit_error
                self.shutdown_calls = []

            def submit(self, *_args, **_kwargs):
                if self.submit_error is not None:
                    raise self.submit_error
                return self.pending.pop(0)

            def shutdown(self, **kwargs):
                self.shutdown_calls.append(kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries = [self.entry(root, "A.class"), self.entry(root, "B.class")]
            self.assertEqual(
                oracle._parse_entry_batch(
                    [], "sha", "javap", "21", Event(), None, None,
                ),
                ([], 0, False, False),
            )
            result = {"rows": [], "failures": [], "completed": True, "parsed": True}

            futures = []
            for entry in entries:
                future = Mock()
                future.cancelled.return_value = False
                future.result.return_value = [result]
                futures.append(future)
            executor = FakeExecutor(futures)
            with patch.object(oracle, "ThreadPoolExecutor", return_value=executor), patch.object(
                oracle.os, "cpu_count", return_value=None,
            ):
                results, workers, timed_out, interrupted = oracle._parse_entry_batch(
                    entries, "sha", "javap", "21", Event(), None, None,
                    batch_javap=False,
                )
            self.assertEqual(workers, 1)
            self.assertFalse(timed_out)
            self.assertFalse(interrupted)
            self.assertEqual(results, [result, result])
            self.assertEqual(executor.shutdown_calls, [{"wait": True, "cancel_futures": True}])

            future = Mock()
            future.cancelled.return_value = True
            executor = FakeExecutor((future,))
            with patch.object(oracle, "ThreadPoolExecutor", return_value=executor), patch.object(
                oracle, "_javap_batch_groups", return_value=[entries],
            ), patch.object(oracle.time, "perf_counter", return_value=10):
                event = Event()
                results, _workers, timed_out, _interrupted = oracle._parse_entry_batch(
                    entries, "sha", "javap", "21", event, 5, 1,
                )
            self.assertTrue(timed_out)
            self.assertTrue(event.is_set())
            self.assertEqual(results, [None, None])

            future = Mock()
            future.cancelled.return_value = False
            future.result.side_effect = (
                oracle.FutureTimeoutError(),
                [result, result],
            )
            executor = FakeExecutor((future,))
            with patch.object(oracle, "ThreadPoolExecutor", return_value=executor), patch.object(
                oracle, "_javap_batch_groups", return_value=[entries],
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                event = Event()
                results, _workers, timed_out, _interrupted = oracle._parse_entry_batch(
                    entries, "sha", "javap", "21", event, 5, 1,
                )
            self.assertTrue(timed_out)
            self.assertTrue(event.is_set())
            self.assertEqual(results, [result, result])

            future = Mock()
            future.cancelled.return_value = False
            future.result.side_effect = RuntimeError("worker failed")
            executor = FakeExecutor((future,))
            with patch.object(oracle, "ThreadPoolExecutor", return_value=executor), patch.object(
                oracle, "_javap_batch_groups", return_value=[entries],
            ):
                results, _workers, _timed_out, _interrupted = oracle._parse_entry_batch(
                    entries, "sha", "javap", "21", Event(), None, 1,
                )
            self.assertTrue(all("worker failed" in item["failures"][0] for item in results))

            future = Mock()
            future.cancelled.return_value = False
            future.result.side_effect = KeyboardInterrupt()
            executor = FakeExecutor((future,))
            with patch.object(oracle, "ThreadPoolExecutor", return_value=executor), patch.object(
                oracle, "_javap_batch_groups", return_value=[entries],
            ):
                event = Event()
                results, _workers, _timed_out, interrupted = oracle._parse_entry_batch(
                    entries, "sha", "javap", "21", event, None, 1,
                )
            self.assertTrue(interrupted)
            self.assertTrue(event.is_set())
            self.assertEqual(results, [None, None])

            executor = FakeExecutor(submit_error=RuntimeError("submit failed"))
            with patch.object(oracle, "ThreadPoolExecutor", return_value=executor), patch.object(
                oracle, "_javap_batch_groups", return_value=[entries],
            ):
                event = Event()
                with self.assertRaisesRegex(RuntimeError, "submit failed"):
                    oracle._parse_entry_batch(
                        entries, "sha", "javap", "21", event, None, 1,
                    )
            self.assertTrue(event.is_set())
            self.assertEqual(executor.shutdown_calls, [{"wait": True, "cancel_futures": True}])


class FinalArtifactSnapshotStateBoundaryTest(unittest.TestCase):
    @staticmethod
    def entry(root: Path, name: str):
        return oracle.PackagedClass(name, root / name, b"content", False)

    @staticmethod
    def edge(
        caller_owner: str | None,
        caller_member: str | None,
        caller_descriptor: str | None,
        callee_owner: str,
        callee_member: str,
        callee_descriptor: str,
        offset: int,
    ):
        return {
            "artifact_sha256": "digest",
            "artifact_entry": "A.class",
            "caller_owner": caller_owner,
            "caller_member": caller_member,
            "caller_descriptor": caller_descriptor,
            "callee_owner": callee_owner,
            "callee_member": callee_member,
            "callee_descriptor": callee_descriptor,
            "opcode_family": "invokestatic",
            "instruction_offset": offset,
        }

    @staticmethod
    def call(**values):
        defaults = dict(
            snapshot=io.BytesIO(),
            digest="digest",
            javap="javap",
            max_workers=None,
            selected_targets=None,
            excluded_nested_jars=None,
            include_nested_runtime_jars=True,
            include_structural_facts=False,
            cache_result=False,
            started_at=0.0,
            budget=0.0,
            deadline=None,
        )
        defaults.update(values)
        return oracle._scan_final_artifact_snapshot(**defaults)

    def setUp(self):
        oracle.clear_immutable_oracle_cache()

    def tearDown(self):
        oracle.clear_immutable_oracle_cache()

    def test_version_deadline_empty_authority_and_exclusion_normalization(self):
        with patch.object(oracle.time, "perf_counter", return_value=10):
            result = self.call(started_at=0, budget=5, deadline=5)
        self.assertTrue(result["timed_out"])

        with patch.object(oracle, "_javap_version_cache_key", return_value=("empty", 0, 0, 0)), patch.object(
            oracle, "_javap_version", return_value="",
        ), patch.object(oracle.time, "perf_counter", return_value=1):
            result = self.call(started_at=0)
        self.assertFalse(result["complete"])
        self.assertEqual(result["failures"], ["oracle_javap_version_empty"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("normalize", 0, 0, 0),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([], []),
            ) as extract:
                result = self.call(
                    excluded_nested_jars={None, "", "  ", " nested.jar "},
                    selected_targets=["bad", {"owner": "", "member": "x"}],
                    started_at=0,
                )
            self.assertTrue(result["complete"])
            self.assertEqual(
                extract.call_args.kwargs["excluded_nested_jars"], {"nested.jar"},
            )

            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("truthy-exclusion", 0, 0, 0),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([], []),
            ) as extract:
                self.call(excluded_nested_jars={"nested.jar"}, started_at=0)
            self.assertEqual(
                extract.call_args.kwargs["excluded_nested_jars"], {"nested.jar"},
            )

    def test_empty_scan_cache_hit_disabled_cache_and_structural_serialization(self):
        structural_result = {
            "rows": [],
            "failures": [],
            "completed": True,
            "parsed": True,
            "structural_facts": {
                "type_edges": {("owner", "member")},
                "class_names": {"owner"},
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            entry = self.entry(Path(temporary), "A.class")
            common = (
                patch.object(
                    oracle, "_javap_version_cache_key", return_value=("cache", 1, 1, 1),
                ),
                patch.object(oracle, "_javap_version", return_value="javap 21"),
                patch.object(oracle, "_extract_packaged_classes", return_value=([entry], [])),
                patch.object(
                    oracle, "_parse_entry_batch",
                    return_value=([structural_result], 1, False, False),
                ),
            )
            with common[0], common[1], common[2] as extract, common[3]:
                first = self.call(
                    cache_result=True,
                    include_structural_facts=True,
                    started_at=0,
                )
                second = self.call(
                    cache_result=True,
                    include_structural_facts=True,
                    started_at=0,
                )
            self.assertTrue(first["complete"])
            self.assertEqual(first["cache_misses"], 1)
            self.assertEqual(second["cache_hits"], 1)
            self.assertEqual(second["cached_class_count"], 1)
            self.assertIn("structural_facts", second)
            self.assertEqual(extract.call_count, 1)

            oracle.clear_immutable_oracle_cache()
            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("disabled", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([], []),
            ) as extract:
                self.call(cache_result=False, started_at=0)
                self.call(cache_result=False, started_at=0)
            self.assertEqual(extract.call_count, 2)

    def test_full_scan_result_aggregation_incomplete_timeout_and_interrupt_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries = [self.entry(root, "A.class"), self.entry(root, "B.class")]
            good = {
                "rows": [self.edge(
                    "caller.Owner", "call", "()V",
                    "target.Owner", "run", "()V", 1,
                )],
                "failures": ["parse failure"],
                "completed": True,
                "parsed": True,
                "structural_facts": {"class_names": {"caller/Owner"}},
            }
            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("full", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=(entries, ["extract warning"]),
            ), patch.object(
                oracle, "_parse_entry_batch",
                return_value=([good, None], 2, False, False),
            ):
                result = self.call(include_structural_facts=True, started_at=0)
            self.assertFalse(result["complete"])
            self.assertEqual(result["completed_class_count"], 1)
            self.assertEqual(result["parsed_class_count"], 1)
            self.assertEqual(result["parse_failure_count"], 1)
            self.assertIn("oracle_parse_incomplete", result["failures"])
            self.assertIn("structural_facts", result)

            for flags, expected in (
                ((True, False), "oracle_time_budget_exceeded"),
                ((False, True), "oracle_interrupted"),
            ):
                timed_out, interrupted = flags
                with patch.object(
                    oracle, "_javap_version_cache_key", return_value=(str(flags), 1, 1, 1),
                ), patch.object(
                    oracle, "_javap_version", return_value="javap 21",
                ), patch.object(
                    oracle, "_extract_packaged_classes", return_value=(entries, []),
                ), patch.object(
                    oracle, "_parse_entry_batch",
                    return_value=([None, None], 1, timed_out, interrupted),
                ):
                    result = self.call(started_at=0, budget=2)
                self.assertTrue(any(item.startswith(expected) for item in result["failures"]))

    def test_post_extraction_deadline_and_full_scan_incomplete_deadline_classification(self):
        def perf_counter(values):
            iterator = iter(values)
            last = values[-1]
            return lambda: next(iterator, last)

        with tempfile.TemporaryDirectory() as temporary:
            entry = self.entry(Path(temporary), "A.class")
            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("post-timeout", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([entry], []),
            ), patch.object(
                oracle.time, "perf_counter", side_effect=perf_counter([0, 20]),
            ):
                result = self.call(started_at=0, budget=10, deadline=10)
            self.assertTrue(result["timed_out"])

            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("future-incomplete", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([entry], []),
            ), patch.object(
                oracle, "_parse_entry_batch", return_value=([None], 1, False, False),
            ), patch.object(oracle.time, "perf_counter", return_value=0):
                result = self.call(started_at=0, budget=100, deadline=100)
            self.assertIn("oracle_parse_incomplete", result["failures"])
            self.assertFalse(result["timed_out"])

            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("batch-timeout", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([entry], []),
            ), patch.object(
                oracle, "_parse_entry_batch", return_value=([None], 1, False, False),
            ), patch.object(
                oracle.time, "perf_counter", side_effect=perf_counter([0, 0, 20]),
            ):
                result = self.call(started_at=0, budget=10, deadline=10)
            self.assertTrue(result["timed_out"])

    def test_selected_target_reverse_closure_candidates_and_batch_state_matrix(self):
        target = {"owner": "target.Owner", "member": "run", "descriptor": "()V"}
        middle = self.edge(
            "middle.Owner", "bridge", "()V",
            "target.Owner", "run", "()V", 2,
        )
        root_edge = self.edge(
            "", "", "",
            "middle.Owner", "bridge", "()V", 1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entries = [self.entry(root, name) for name in ("A.class", "B.class")]
            batch_results = [
                {
                    "rows": [root_edge, middle],
                    "failures": [],
                    "completed": False,
                    "parsed": True,
                },
                None,
            ]
            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("selected", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=(entries, []),
            ), patch.object(
                oracle, "_entry_might_reference", return_value=True,
            ), patch.object(
                oracle, "_parse_entry_batch",
                return_value=(batch_results, 2, False, False),
            ) as batch:
                result = self.call(selected_targets=[target], started_at=0)
            self.assertEqual(batch.call_count, 1)
            self.assertIn("oracle_parse_incomplete", result["failures"])
            self.assertEqual(result["class_count"], 2)
            self.assertEqual(len(result["edges"]), 2)

            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("no-candidate", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=(entries, []),
            ), patch.object(
                oracle, "_entry_might_reference", return_value=False,
            ), patch.object(oracle, "_parse_entry_batch") as batch:
                result = self.call(selected_targets=[target], started_at=0)
            batch.assert_not_called()
            self.assertEqual(result["class_count"], 0)
            self.assertTrue(result["complete"])

            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("selected-timeout", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=(entries, []),
            ), patch.object(
                oracle, "_entry_might_reference", return_value=True,
            ), patch.object(
                oracle, "_parse_entry_batch",
                return_value=([None, None], 1, True, True),
            ):
                result = self.call(selected_targets=[target], started_at=0, budget=1)
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["interrupted"])

            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("selected-empty", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([], []),
            ):
                result = self.call(selected_targets=[target], started_at=0)
            self.assertEqual(result["class_count"], 0)
            self.assertTrue(result["complete"])

            def perf_counter():
                values = iter((0, 0, 20))
                return lambda: next(values, 20)

            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("selected-post-timeout", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=(entries, []),
            ), patch.object(
                oracle.time, "perf_counter", side_effect=perf_counter(),
            ), patch.object(oracle, "_parse_entry_batch") as batch:
                result = self.call(
                    selected_targets=[target], started_at=0, budget=10, deadline=10,
                )
            batch.assert_not_called()
            self.assertTrue(result["timed_out"])

            empty_caller = self.edge(
                "", "", "", "target.Owner", "run", "()V", 3,
            )
            only_result = {
                "rows": [empty_caller], "failures": [],
                "completed": True, "parsed": True,
                "structural_facts": {"class_names": {"target/Owner"}},
            }
            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("empty-caller", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([entries[0]], []),
            ), patch.object(
                oracle, "_entry_might_reference", return_value=True,
            ), patch.object(
                oracle, "_parse_entry_batch",
                return_value=([only_result], 1, False, False),
            ):
                result = self.call(
                    selected_targets=[target], include_structural_facts=True,
                    started_at=0,
                )
            self.assertEqual(len(result["edges"]), 1)
            self.assertIn("structural_facts", result)

    def test_scan_falsey_exclusions_empty_rows_and_interrupt_only_state(self):
        with patch.object(
            oracle, "_javap_version_cache_key", return_value=("falsey-exclusion", 1, 1, 1),
        ), patch.object(
            oracle, "_javap_version", return_value="javap 21",
        ), patch.object(
            oracle, "_extract_packaged_classes", return_value=([], []),
        ) as extract:
            result = self.call(excluded_nested_jars={None}, started_at=0)
        self.assertTrue(result["complete"])
        self.assertEqual(extract.call_args.kwargs["excluded_nested_jars"], set())

        target = {"owner": "target.Owner", "member": "run", "descriptor": "()V"}
        empty_result = {
            "rows": [], "failures": [], "completed": True, "parsed": True,
            "structural_facts": {},
        }
        with tempfile.TemporaryDirectory() as temporary:
            entry = self.entry(Path(temporary), "A.class")
            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("empty-rows", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([entry], []),
            ), patch.object(
                oracle, "_entry_might_reference", return_value=True,
            ), patch.object(
                oracle, "_parse_entry_batch",
                return_value=([empty_result], 1, False, False),
            ):
                empty = self.call(
                    selected_targets=[target], include_structural_facts=True,
                    started_at=0,
                )
            self.assertTrue(empty["complete"])
            self.assertEqual(empty["edges"], [])

            with patch.object(
                oracle, "_javap_version_cache_key", return_value=("interrupt-only", 1, 1, 1),
            ), patch.object(
                oracle, "_javap_version", return_value="javap 21",
            ), patch.object(
                oracle, "_extract_packaged_classes", return_value=([entry], []),
            ), patch.object(
                oracle, "_entry_might_reference", return_value=True,
            ), patch.object(
                oracle, "_parse_entry_batch", return_value=([None], 1, False, True),
            ):
                interrupted = self.call(
                    selected_targets=[target], started_at=0,
                )
            self.assertTrue(interrupted["interrupted"])
            self.assertFalse(interrupted["timed_out"])
            self.assertNotIn("oracle_parse_incomplete", interrupted["failures"])


if __name__ == "__main__":
    unittest.main()
