import random
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from signature_utils import (  # noqa: E402
    canonical_api_identity,
    normalize_signature_for_identity,
    normalize_signature_for_lookup,
    signatures_match_identity,
)


class SemanticPropertyTest(unittest.TestCase):
    def test_signature_normalization_is_idempotent(self):
        rng = random.Random(20260809)
        types = ("String", "java.lang.String", "com.acme.Value", "int", "long")
        for _ in range(250):
            signature = "( " + " , ".join(
                rng.choice(types) for _ in range(rng.randrange(5))
            ) + " )"
            identity = normalize_signature_for_identity(signature)
            lookup = normalize_signature_for_lookup(signature)
            self.assertEqual(normalize_signature_for_identity(identity), identity)
            self.assertEqual(normalize_signature_for_lookup(lookup), lookup)

    def test_canonical_api_identity_is_whitespace_and_case_stable(self):
        first = canonical_api_identity({
            "coord": " com.acme:api ",
            "api_name": "com.acme.Target.call",
            "api_signature": "( java.lang.String )",
            "symbol_kind": "METHOD",
        })
        second = canonical_api_identity({
            "coord": "com.acme:api",
            "api_name": "com.acme.Target.call",
            "api_signature": "(java.lang.String)",
            "symbol_kind": "method",
        })
        self.assertEqual(first, second)

    def test_signature_match_never_changes_arity(self):
        self.assertTrue(signatures_match_identity("(String,int)", "(java.lang.String,int)"))
        self.assertFalse(signatures_match_identity("(String,int)", "(java.lang.String)"))


if __name__ == "__main__":
    unittest.main()
