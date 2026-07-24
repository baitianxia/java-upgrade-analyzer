import re
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from diagnostic_contract import (  # noqa: E402
    DEPENDENCY_COORDINATES_UNRESOLVED,
    SPRING_RUNTIME_CLASS_AMBIGUOUS,
    canonical_reason_code,
    diagnostic_contract_metadata,
    normalize_component_reason_codes,
    normalize_diagnostic_payload,
)


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
        self.assertEqual(
            SPRING_RUNTIME_CLASS_AMBIGUOUS,
            canonical_reason_code("SPRING_PACKAGED_CLASS_AMBIGUOUS"),
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
                "SPRING_PACKAGED_CLASS_AMBIGUOUS",
            ],
        })

        self.assertEqual(
            [
                DEPENDENCY_COORDINATES_UNRESOLVED,
                SPRING_RUNTIME_CLASS_AMBIGUOUS,
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
            SPRING_RUNTIME_CLASS_AMBIGUOUS,
            "MYBATIS_RUNTIME_ARTIFACT_PARSE_FAILED",
        ):
            self.assertIsNotNone(pattern.fullmatch(code))


if __name__ == "__main__":
    unittest.main()
