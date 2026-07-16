import sys
import csv
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import exhaustive_api_oracle as oracle  # noqa: E402


def authority(api_name, signature, conclusion, authority="jdk-javap"):
    return {
        "coord": "g:a",
        "api_name": api_name,
        "api_signature": signature,
        "symbol_kind": "method",
        "oracle_conclusion": conclusion,
        "authority": authority,
        "authority_version": "21.0.2",
        "procedure": "javap -c -s target/classes",
        "evidence_path": "evidence/javap.txt",
        "evidence_sha256": "a" * 64,
        "generated_at": "2026-07-11T00:00:00Z",
        "evidence_mode": "bytecode",
    }


class ExhaustiveApiOracleTest(unittest.TestCase):
    def test_canonical_identity_includes_owner_signature_and_kind(self):
        row = {
            "coord": "g:a", "api_name": "p.Owner.call",
            "api_signature": "(java.lang.String)", "symbol_kind": "method",
        }

        self.assertEqual(
            oracle.canonical_identity(row),
            "g:a|p.Owner.call|(java.lang.String)|method|",
        )

    def test_audit_verifies_every_api_with_third_party_provenance(self):
        changed = [
            {"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method"},
            {"coord": "g:a", "api_name": "p.A.two", "api_signature": "(int)", "symbol_kind": "method"},
        ]
        analyzed = [
            {**changed[0], "analysis_status": "reachable"},
            {**changed[1], "analysis_status": "reachable"},
        ]
        authorities = [
            authority("p.A.one", "()", "reachable"),
            authority("p.A.two", "(int)", "reachable", authority="project-tests"),
        ]

        result = oracle.audit_api_oracle(changed, analyzed, authorities)

        self.assertEqual(result["selected"], 2)
        self.assertEqual(result["verified"], 2)
        self.assertEqual(result["unverified"], 0)
        self.assertFalse(result["blocking"])

    def test_self_certified_and_missing_records_are_unverified(self):
        changed = [
            {"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method"},
            {"coord": "g:a", "api_name": "p.A.two", "api_signature": "()", "symbol_kind": "method"},
        ]
        analyzed = [{**row, "analysis_status": "reachable"} for row in changed]
        self_record = authority("p.A.one", "()", "reachable", authority="java-upgrade-analyzer")

        result = oracle.audit_api_oracle(changed, analyzed, [self_record])

        self.assertEqual(result["verified"], 0)
        self.assertEqual(result["unverified"], 2)
        self.assertEqual(len(result["invalid_provenance"]), 1)
        self.assertTrue(result["blocking"])

    def test_analyzer_identity_outside_changed_population_is_blocking(self):
        changed = [
            {"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method"}
        ]
        extra = {
            "coord": "g:a", "api_name": "p.A.extra", "api_signature": "()",
            "symbol_kind": "method", "analysis_status": "reachable",
        }
        analyzed = [{**changed[0], "analysis_status": "reachable"}, extra]

        result = oracle.audit_api_oracle(
            changed, analyzed, [authority("p.A.one", "()", "reachable")]
        )

        self.assertEqual(result["analyzer_extra_identity_count"], 1)
        self.assertEqual(
            result["analyzer_extra_identities"],
            ["g:a|p.A.extra|()|method|"],
        )
        self.assertTrue(result["blocking"])

    def test_missing_analyzer_identity_is_an_explicit_closed_world_failure(self):
        changed = [
            {"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method"},
            {"coord": "g:a", "api_name": "p.A.two", "api_signature": "()", "symbol_kind": "method"},
        ]
        analyzed = [{**changed[0], "analysis_status": "reachable"}]

        result = oracle.audit_api_oracle(
            changed,
            analyzed,
            [
                authority("p.A.one", "()", "reachable"),
                authority("p.A.two", "()", "reachable"),
            ],
        )

        self.assertEqual(
            result["analyzer_missing_identities"],
            ["g:a|p.A.two|()|method|"],
        )
        self.assertEqual(result["analyzer_missing_identity_count"], 1)
        self.assertTrue(result["blocking"])

    def test_duplicate_changed_identity_is_an_explicit_closed_world_failure(self):
        changed = [
            {"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method"}
        ]
        analyzed = [{**changed[0], "analysis_status": "reachable"}]

        result = oracle.audit_api_oracle(
            changed + changed,
            analyzed,
            [authority("p.A.one", "()", "reachable")],
        )

        self.assertEqual(
            result["changed_duplicate_identities"],
            ["g:a|p.A.one|()|method|"],
        )
        self.assertEqual(result["changed_duplicate_identity_count"], 1)
        self.assertTrue(result["blocking"])

    def test_duplicate_analyzer_identity_with_conflicting_conclusions_is_blocking(self):
        changed = [
            {"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method"}
        ]
        analyzed = [
            {**changed[0], "analysis_status": "reachable"},
            {**changed[0], "analysis_status": "not_impacted"},
        ]

        result = oracle.audit_api_oracle(
            changed, analyzed, [authority("p.A.one", "()", "not_impacted")]
        )

        self.assertEqual(result["analyzer_duplicate_identity_count"], 1)
        self.assertEqual(result["analyzer_conflict_identity_count"], 1)
        self.assertTrue(result["blocking"])

    def test_conflicting_authorities_do_not_use_majority_vote(self):
        changed = [{"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method"}]
        analyzed = [{**changed[0], "analysis_status": "reachable"}]
        records = [
            authority("p.A.one", "()", "reachable", authority="jdk-javap"),
            authority("p.A.one", "()", "not_found_in_static_analysis", authority="project-tests"),
            authority("p.A.one", "()", "reachable", authority="independent-engine"),
        ]

        result = oracle.audit_api_oracle(changed, analyzed, records)

        self.assertEqual(result["oracle_conflicts"], 1)
        self.assertEqual(result["verified"], 0)
        self.assertEqual(result["ledger"][0]["verdict"], "oracle_conflict")
        self.assertTrue(result["blocking"])

    def test_uncertain_static_authority_does_not_conflict_with_project_test_reachable(self):
        changed = [{"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method"}]
        analyzed = [{**changed[0], "analysis_status": "reachable"}]
        static = authority("p.A.one", "()", "uncertain", authority="final-artifact-classfile")
        project_test = authority("p.A.one", "()", "reachable", authority="project-tests")
        project_test["evidence_mode"] = "project_test"

        result = oracle.audit_api_oracle(changed, analyzed, [static, project_test])

        self.assertEqual(result["oracle_conflicts"], 0)
        self.assertEqual(result["verified"], 1)
        self.assertEqual(result["ledger"][0]["oracle_conclusion"], "reachable")

    def test_runtime_reachable_dominates_static_absence_without_oracle_conflict(self):
        changed = [{
            "coord": "g:a", "api_name": "p.A.one", "api_signature": "()",
            "symbol_kind": "method",
        }]
        analyzed = [{**changed[0], "analysis_status": "reachable"}]
        static = authority(
            "p.A.one", "()", "not_found_in_static_analysis",
            authority="final-artifact-classfile",
        )
        static["conclusion_scope"] = "static_analysis"
        project_test = authority(
            "p.A.one", "()", "reachable", authority="project-runtime",
        )
        project_test["evidence_mode"] = "project_test"

        result = oracle.audit_api_oracle(
            changed, analyzed, [static, project_test]
        )

        self.assertEqual(result["oracle_conflicts"], 0)
        self.assertEqual(result["verified"], 1)
        self.assertEqual(result["ledger"][0]["oracle_conclusion"], "reachable")

    def test_uncertain_static_authority_alone_cannot_verify_reachable(self):
        changed = [{"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method"}]
        analyzed = [{**changed[0], "analysis_status": "reachable"}]
        records = [authority(
            "p.A.one", "()", "uncertain", authority="final-artifact-classfile"
        )]

        result = oracle.audit_api_oracle(changed, analyzed, records)

        self.assertEqual(result["oracle_conflicts"], 0)
        self.assertEqual(result["unverified"], 1)
        self.assertEqual(result["ledger"][0]["verdict"], "unverified")

    def test_negative_conclusion_requires_two_independent_authorities(self):
        changed = [{"coord": "g:a", "api_name": "p.A.one", "api_signature": "()", "symbol_kind": "method", "severity": "P0"}]
        analyzed = [{**changed[0], "analysis_status": "not_found_in_static_analysis"}]
        records = [authority("p.A.one", "()", "not_found_in_static_analysis")]

        result = oracle.audit_api_oracle(changed, analyzed, records)

        self.assertEqual(result["unverified"], 1)
        self.assertEqual(result["ledger"][0]["verdict"], "unverified")

    def test_uncertain_authority_does_not_count_as_support_for_negative_conclusion(self):
        changed = [{
            "coord": "g:a", "api_name": "p.A.one", "api_signature": "()",
            "symbol_kind": "method", "severity": "P0",
        }]
        analyzed = [{**changed[0], "analysis_status": "not_found_in_static_analysis"}]
        records = [
            authority("p.A.one", "()", "not_found_in_static_analysis", authority="jdk-javap"),
            authority("p.A.one", "()", "uncertain", authority="constant-pool-scan"),
        ]

        result = oracle.audit_api_oracle(changed, analyzed, records)

        self.assertEqual(result["unverified"], 1)
        self.assertEqual(result["ledger"][0]["verdict"], "unverified")

    def test_loads_all_step5_states_and_writes_one_ledger_row_per_api(self):
        summary = {
            "reachable_apis": [{"coord": "g:a", "api": "p.A.one", "api_signature": "()", "symbol_kind": "method"}],
            "not_impacted_apis": [{"coord": "g:a", "api": "p.A.two", "api_signature": "()", "symbol_kind": "method"}],
            "uncertain_apis": [], "not_analyzed_apis": [], "not_found_apis": [],
        }
        rows = oracle.load_analyzer_rows(summary)
        audit = oracle.audit_api_oracle(rows, rows, [])

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.csv"
            oracle.write_oracle_ledger(path, audit)
            with path.open(encoding="utf-8", newline="") as fh:
                written = list(csv.DictReader(fh))

        self.assertEqual([row["analysis_status"] for row in rows], ["reachable", "not_impacted"])
        self.assertEqual(len(written), 2)
        self.assertTrue(all(row["verdict"] == "unverified" for row in written))


if __name__ == "__main__":
    unittest.main()
