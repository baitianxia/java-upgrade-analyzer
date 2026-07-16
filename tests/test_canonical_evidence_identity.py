import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import confidence_weighted_tracer as tracer  # noqa: E402
import exhaustive_api_oracle as exhaustive  # noqa: E402
import indirect_usage_analyzer as indirect  # noqa: E402
import real_project_regression as realreg  # noqa: E402
import signature_utils  # noqa: E402
import third_party_jdeps_oracle as jdeps  # noqa: E402


def equivalent_rows():
    return (
        {
            "coord": " com.acme:api ",
            "api_name": "com.acme.Outer$Inner.call",
            "api_signature": (
                "( java.util.List<java.lang.String>, java.lang.String... )"
            ),
            "symbol_kind": "METHOD",
            "change_type": " removed ",
        },
        {
            "coord": "com.acme:api",
            "api_name": "com.acme.Outer.Inner.call",
            "api_signature": "(java.util.List,java.lang.String[])",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        },
    )


class CanonicalEvidenceIdentityInvariantTest(unittest.TestCase):
    def producer_identities(self, row):
        canonical = signature_utils.canonical_api_identity(row)
        return {
            "shared": canonical,
            "tracer": tracer.build_api_identity_key(row),
            "indirect": indirect.api_key(row),
            "exhaustive": exhaustive.canonical_identity(row),
            "real_project": realreg.serialized_api_identity(row),
            "jdeps": jdeps.serialized_api_identity(row),
        }

    def test_equivalent_source_and_bytecode_spellings_have_one_identity(self):
        first, second = equivalent_rows()

        first_identities = self.producer_identities(first)
        second_identities = self.producer_identities(second)

        self.assertEqual(first_identities, second_identities)
        self.assertEqual(
            signature_utils.canonical_api_identity_tuple(first),
            (
                "com.acme:api",
                "com.acme.Outer.Inner.call",
                "(java.util.List,java.lang.String[])",
                "method",
                "REMOVED",
            ),
        )

    def test_pinned_real_project_semantic_oracles_use_canonical_identity(self):
        violations = []
        fixture_root = ROOT / "tests" / "fixtures" / "real_projects"
        for path in sorted(fixture_root.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            for index, row in enumerate(
                payload.get("canonical_semantic_references") or ()
            ):
                identity = str(row.get("api_identity") or "")
                if len(identity.split("|")) != 5 or identity.startswith("("):
                    violations.append(f"{path.name}:{index}:{identity}")

        self.assertEqual(violations, [])

    def test_different_change_types_never_collapse_in_any_producer(self):
        first, second = equivalent_rows()
        second = {**second, "change_type": "SIGNATURE_CHANGED"}

        first_identities = self.producer_identities(first)
        second_identities = self.producer_identities(second)

        for producer in first_identities:
            with self.subTest(producer=producer):
                self.assertNotEqual(
                    first_identities[producer],
                    second_identities[producer],
                )

    def test_dropping_change_identity_from_oracle_fails_closed(self):
        changed = {
            "coord": "com.acme:api",
            "api_name": "com.acme.Api.call",
            "api_signature": "()",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }
        analyzer = {**changed, "analysis_status": "reachable"}
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "javap.txt"
            evidence.write_text("physical evidence\n", encoding="utf-8")
            oracle_row = {
                key: value for key, value in changed.items()
                if key != "change_type"
            }
            oracle_row.update({
                "oracle_conclusion": "reachable",
                "authority": "jdk-javap",
                "authority_version": "24",
                "procedure": "javap -c -s target.class",
                "evidence_path": str(evidence),
                "evidence_sha256": "a" * 64,
                "generated_at": "2026-07-16",
            })

            audit = exhaustive.audit_api_oracle(
                [changed],
                [analyzer],
                [oracle_row],
            )

        self.assertTrue(audit["blocking"])
        self.assertEqual(audit["verified"], 0)
        self.assertEqual(audit["missing_identity_count"], 1)
        self.assertEqual(audit["extra_identity_count"], 1)

    def test_trace_envelope_uses_canonical_target_identity(self):
        first, _second = equivalent_rows()
        draft = tracer._new_trace_draft(first)

        self.assertEqual(
            tracer._trace_target_identity(draft),
            signature_utils.canonical_api_identity(first),
        )


if __name__ == "__main__":
    unittest.main()
