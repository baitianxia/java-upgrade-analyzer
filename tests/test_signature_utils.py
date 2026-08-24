import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import signature_utils as signatures  # noqa: E402


class SignatureUtilsBoundaryTest(unittest.TestCase):
    def test_descriptor_type_covers_every_primitive_object_and_array_shape(self):
        primitives = {
            "B": "byte",
            "C": "char",
            "D": "double",
            "F": "float",
            "I": "int",
            "J": "long",
            "S": "short",
            "Z": "boolean",
            "V": "void",
        }
        for marker, expected in primitives.items():
            with self.subTest(marker=marker):
                self.assertEqual(
                    signatures._jvm_descriptor_type(marker, 0),
                    (expected, 1),
                )
        self.assertEqual(
            signatures._jvm_descriptor_type("xx[[Ljava/lang/Outer$Inner;tail", 2),
            ("java.lang.Outer.Inner[][]", 27),
        )

    def test_descriptor_type_rejects_truncation_void_array_and_invalid_object_names(self):
        invalid = (
            "",
            "[",
            "[V",
            "Q",
            "Lmissing",
            "L;",
            "Lbad.name;",
            "L/bad;",
            "Lbad/;",
            "Lbad[/Name;",
        )
        for descriptor in invalid:
            with self.subTest(descriptor=descriptor), self.assertRaisesRegex(
                ValueError, "invalid_jvm_descriptor"
            ):
                signatures._jvm_descriptor_type(descriptor, 0)

    def test_method_descriptor_valid_matrix_has_exact_java_parameter_form(self):
        cases = {
            "()V": "()",
            "(BCDFIJSZ)V": "(byte,char,double,float,int,long,short,boolean)",
            "([I[[Ljava/lang/String;)Ljava/lang/Object;":
                "(int[],java.lang.String[][])",
            "(Ldemo/Outer$Inner;)I": "(demo.Outer.Inner)",
        }
        for descriptor, expected in cases.items():
            with self.subTest(descriptor=descriptor):
                self.assertEqual(
                    signatures.jvm_method_parameter_signature(descriptor),
                    expected,
                )

    def test_method_descriptor_rejects_every_malformed_boundary(self):
        invalid = (
            None,
            "",
            "I)V",
            "(I",
            "(V)V",
            "([V)V",
            "(I))V",
            "()",
            "()Q",
            "()Ljava/lang/String",
            "()L;",
            "()Vx",
            "(Ljava/lang/String)V",
            "(Lfoo)bar;)V",
            "([I)Vextra",
        )
        for descriptor in invalid:
            with self.subTest(descriptor=descriptor), self.assertRaisesRegex(
                ValueError, "invalid_(method|jvm)_descriptor"
            ):
                signatures.jvm_method_parameter_signature(descriptor)

    def test_split_signature_params_handles_nested_generics_and_empty_arity(self):
        cases = {
            "()": [],
            "(   )": [],
            "(String)": ["String"],
            "( Map<String,List<Integer>> , int )":
                ["Map<String,List<Integer>>", "int"],
            "(A<B<C,D>>,E<F>)": ["A<B<C,D>>", "E<F>"],
        }
        for signature, expected in cases.items():
            with self.subTest(signature=signature):
                self.assertEqual(
                    signatures.split_signature_params(signature), expected
                )

        invalid = (
            None,
            "",
            "String",
            "(>)",
            "(List<String)",
            "(,String)",
            "(String,)",
            "(String,,int)",
        )
        for signature in invalid:
            with self.subTest(signature=signature):
                self.assertIsNone(signatures.split_signature_params(signature))

    def test_lookup_normalization_erases_generics_qualification_and_varargs(self):
        cases = {
            None: "",
            "bad": "",
            "(bad": "",
            "()": "()",
            "(java.lang.String, com.acme.Dto...)": "(String, Dto[])",
            "(java.util.Map<java.lang.String,com.acme.Dto>,int)": "(Map, int)",
            "(List<String)": "",
        }
        for signature, expected in cases.items():
            with self.subTest(signature=signature):
                self.assertEqual(
                    signatures.normalize_signature_for_lookup(signature), expected
                )

    def test_identity_normalization_preserves_qualification_and_erases_generics(self):
        cases = {
            None: "",
            "bad": "",
            "()": "()",
            "( java.util.Map < String , List<Integer> > , demo.Outer$Inner... )":
                "(java.util.Map,demo.Outer.Inner[])",
            "(A<B<C>>, D)": "(A,D)",
        }
        for signature, expected in cases.items():
            with self.subTest(signature=signature):
                self.assertEqual(
                    signatures.normalize_signature_for_identity(signature), expected
                )

    def test_identity_matching_is_symmetric_only_for_missing_leading_qualification(self):
        true_pairs = (
            ("()", "()"),
            ("(String,int)", "(java.lang.String,int)"),
            ("(java.lang.String)", "(String)"),
            ("(demo.Outer$Inner...)", "(Outer.Inner[])"),
        )
        for left, right in true_pairs:
            with self.subTest(left=left, right=right):
                self.assertTrue(signatures.signatures_match_identity(left, right))
                self.assertTrue(signatures.signatures_match_identity(right, left))

        false_pairs = (
            (None, "()"),
            ("()", None),
            ("bad", "()"),
            ("(String,int)", "(String)"),
            ("(left.Type)", "(right.Type)"),
            ("(String)", "(StringBuilder)"),
        )
        for left, right in false_pairs:
            with self.subTest(left=left, right=right):
                self.assertFalse(signatures.signatures_match_identity(left, right))

    def test_constructor_and_api_identity_cover_aliases_and_malformed_signatures(self):
        constructor_cases = {
            None: "",
            "": "",
            "demo.Widget": "demo.Widget.<init>",
            "demo.Widget.Widget": "demo.Widget.<init>",
            "demo.Outer$Inner": "demo.Outer.Inner.<init>",
            "demo.Widget.<init>": "demo.Widget.<init>",
        }
        for api_name, expected in constructor_cases.items():
            with self.subTest(api_name=api_name):
                self.assertEqual(
                    signatures._canonical_constructor_name(api_name), expected
                )

        self.assertEqual(
            signatures.canonical_api_identity_tuple(None),
            ("", "", "", "", ""),
        )
        self.assertEqual(
            signatures.canonical_api_identity_tuple({
                "coord": " g:a:1 ",
                "symbol_kind": " CONSTRUCTOR ",
                "api": "demo.Widget.Widget",
                "api_signature": " ( java.lang.String ",
                "change_type": " removed ",
            }),
            (
                "g:a:1",
                "demo.Widget.<init>",
                "(java.lang.String",
                "constructor",
                "REMOVED",
            ),
        )
        self.assertEqual(
            signatures.canonical_api_identity({
                "api_name": "demo.Type$Nested.call",
                "api_signature": "()",
                "symbol_kind": "method",
            }),
            "|demo.Type.Nested.call|()|method|",
        )


if __name__ == "__main__":
    unittest.main()
