import re
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from diagnostic_contract import (  # noqa: E402
    DEPENDENCY_COORDINATES_UNRESOLVED,
    canonical_reason_code,
    diagnostic_contract_metadata,
    normalize_component_reason_codes,
    normalize_diagnostic_payload,
)
import diagnostic_contract  # noqa: E402


class DiagnosticContractTest(unittest.TestCase):
    def test_snake_camel_and_kebab_inputs_share_upper_snake_output(self):
        self.assertEqual(
            "STEP1_REMOTE_FETCH_FAILED",
            canonical_reason_code("step1RemoteFetchFailed"),
        )
        self.assertEqual(
            "STEP1_REMOTE_FETCH_FAILED",
            canonical_reason_code("step1-remote-fetch-failed"),
        )
        self.assertEqual(
            "STEP1_REMOTE_FETCH_FAILED",
            canonical_reason_code("step1_remote_fetch_failed"),
        )

    def test_published_legacy_codes_resolve_to_semantic_canonical_codes(self):
        self.assertEqual(
            DEPENDENCY_COORDINATES_UNRESOLVED,
            canonical_reason_code(
                "unresolved_dependency_coordinates_after_enrichment"
            ),
        )

    def test_interaction_payload_exposes_contract_and_legacy_alias(self):
        payload = normalize_diagnostic_payload(
            {"reason_code": "step4GitRefsNeedConfirmation"},
            origin_step="step4",
        )

        self.assertEqual("STEP4_GIT_REFS_NEED_CONFIRMATION", payload["reason_code"])
        self.assertEqual(["step4GitRefsNeedConfirmation"], payload["reason_code_aliases"])
        self.assertEqual("step4", payload["origin_step"])
        self.assertEqual(
            "UPPER_SNAKE_CASE",
            payload["diagnostic_contract"]["reason_code_style"],
        )

    def test_coverage_component_is_canonical_and_keeps_aliases(self):
        component = normalize_component_reason_codes({
            "reason_codes": [
                "dependency_coordinates_unresolved",
                "BINARY_INDEPENDENT_VALIDATION_FAILED",
            ],
        })

        self.assertEqual(
            [
                "BINARY_INDEPENDENT_VALIDATION_FAILED",
                DEPENDENCY_COORDINATES_UNRESOLVED,
            ],
            component["reason_codes"],
        )
        self.assertEqual(
            ["dependency_coordinates_unresolved"],
            component["reason_code_aliases"][
                DEPENDENCY_COORDINATES_UNRESOLVED
            ],
        )

    def test_contract_pattern_accepts_all_canonical_examples(self):
        metadata = diagnostic_contract_metadata()
        pattern = re.compile(metadata["reason_code_pattern"])
        for code in (
            DEPENDENCY_COORDINATES_UNRESOLVED,
            "DEPENDENCY_SOURCE_REF_UNAVAILABLE",
            "BINARY_INDEPENDENT_VALIDATION_FAILED",
            "BINARY_ARTIFACT_PARSE_FAILED",
        ):
            self.assertIsNotNone(pattern.fullmatch(code))

    def test_empty_alias_duplicate_and_mapping_boundaries_are_deterministic(self):
        self.assertEqual(diagnostic_contract._upper_snake(None), "")
        self.assertEqual(diagnostic_contract._upper_snake(" HTTPServer "), "HTTP_SERVER")
        self.assertEqual(canonical_reason_code(None, default=None), "UNKNOWN")
        self.assertEqual(canonical_reason_code("", default="fallback code"), "FALLBACK_CODE")
        self.assertEqual(
            diagnostic_contract.canonical_reason_codes(
                [None, "", "alpha reason", "ALPHA_REASON"],
            ),
            ["ALPHA_REASON"],
        )
        self.assertEqual(diagnostic_contract.canonical_reason_codes(None), [])
        self.assertEqual(diagnostic_contract.reason_code_aliases("unknown"), [])
        self.assertEqual(
            diagnostic_contract.diagnostic_identity(None, None),
            {
                "diagnostic_schema": diagnostic_contract.DIAGNOSTIC_CONTRACT_SCHEMA,
                "origin_step": "",
                "reason_code": "UNKNOWN",
                "reason_code_aliases": [],
            },
        )

        empty = normalize_diagnostic_payload(None, origin_step=" STEP2 ")
        self.assertEqual(empty["origin_step"], "step2")
        self.assertEqual(empty["reason_code_aliases"], [])
        self.assertEqual(
            empty["diagnostic_schema"],
            diagnostic_contract.DIAGNOSTIC_CONTRACT_SCHEMA,
        )

        aliases = normalize_diagnostic_payload({
            "reason_code": "archive unsafe",
            "origin_step": " STEP3 ",
            "reason_code_aliases": ["legacy", "", "legacy"],
            "reason_codes": ("archive unsafe", "ARCHIVE_UNSAFE", None),
        })
        self.assertEqual(aliases["reason_code"], "ARCHIVE_UNSAFE")
        self.assertEqual(aliases["origin_step"], "step3")
        self.assertEqual(
            aliases["reason_code_aliases"],
            ["legacy", "archive unsafe"],
        )
        self.assertEqual(aliases["reason_codes"], ["ARCHIVE_UNSAFE"])

        published_alias = normalize_diagnostic_payload({
            "reason_code": "unresolved_dependency_coordinates_after_enrichment",
        })
        self.assertEqual(
            published_alias["reason_code"],
            DEPENDENCY_COORDINATES_UNRESOLVED,
        )
        self.assertEqual(
            published_alias["reason_code_aliases"],
            ["unresolved_dependency_coordinates_after_enrichment"],
        )
        canonical_payload = normalize_diagnostic_payload({
            "reason_code": "ARCHIVE_UNSAFE",
        })
        self.assertEqual(canonical_payload["reason_code_aliases"], [])

        preserved_collection = normalize_diagnostic_payload({
            "reason_codes": "not-a-collection-contract",
            "origin_step": "existing",
        }, origin_step="ignored")
        self.assertEqual(
            preserved_collection["reason_codes"],
            "not-a-collection-contract",
        )
        self.assertEqual(preserved_collection["origin_step"], "existing")

        self.assertEqual(
            normalize_component_reason_codes(None),
            {"reason_codes": []},
        )
        component = normalize_component_reason_codes({
            "reason_codes": [
                None,
                "",
                "unresolved_dependency_coordinates_after_enrichment",
                "unresolved_dependency_coordinates_after_enrichment",
                DEPENDENCY_COORDINATES_UNRESOLVED,
            ],
        })
        self.assertEqual(
            component["reason_codes"],
            [DEPENDENCY_COORDINATES_UNRESOLVED],
        )
        self.assertEqual(
            component["reason_code_aliases"],
            {
                DEPENDENCY_COORDINATES_UNRESOLVED: [
                    "unresolved_dependency_coordinates_after_enrichment",
                ],
            },
        )

        self.assertIsNone(diagnostic_contract.normalize_diagnostic_mapping(None))
        self.assertEqual(diagnostic_contract.normalize_diagnostic_mapping({}), {})
        reason_only = diagnostic_contract.normalize_diagnostic_mapping({
            "reason_code": "archive unsafe",
            "reason_codes": "leave-string-unchanged",
        })
        self.assertEqual(reason_only["reason_code"], "ARCHIVE_UNSAFE")
        self.assertEqual(reason_only["reason_codes"], "leave-string-unchanged")
        reasons_only = diagnostic_contract.normalize_diagnostic_mapping({
            "reason_codes": {"archive unsafe", "ARCHIVE_UNSAFE"},
        })
        self.assertEqual(reasons_only["reason_codes"], ["ARCHIVE_UNSAFE"])


if __name__ == "__main__":
    unittest.main()
