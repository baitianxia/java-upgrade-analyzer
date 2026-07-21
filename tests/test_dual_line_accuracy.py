import csv
from contextlib import redirect_stdout
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dual_line_accuracy as dual  # noqa: E402


EVIDENCE_PATH = Path(__file__).resolve()
EVIDENCE_SHA256 = hashlib.sha256(EVIDENCE_PATH.read_bytes()).hexdigest()
ARTIFACT_SHA256 = "a" * 64


def api(name: str, signature: str = "()") -> dict:
    return {
        "coord": "example:library",
        "api_name": name,
        "api_signature": signature,
        "symbol_kind": "method",
        "change_type": "REMOVED",
        "severity": "P1",
    }


def oracle_record(row: dict, conclusion: str = "reachable") -> dict:
    return {
        **row,
        "oracle_conclusion": conclusion,
        "authority": "project-tests",
        "authority_version": "1",
        "procedure": "independent runtime assertion",
        "evidence_path": str(EVIDENCE_PATH),
        "evidence_sha256": EVIDENCE_SHA256,
        "generated_at": "2026-07-21T00:00:00Z",
        "evidence_mode": "project_test",
        "artifact_sha256": ARTIFACT_SHA256,
    }


class DualLineAccuracyTest(unittest.TestCase):
    def test_empty_api_universe_cannot_create_a_fake_success(self):
        result = dual.reconcile_accuracy_lines(
            [], [], [], expected_artifact_sha256=ARTIFACT_SHA256
        )

        self.assertTrue(result["blocking"])
        self.assertIn("api_universe_empty", result["errors"])

    def test_reconciles_arbitrary_project_without_registered_case(self):
        universe = [api("sample.Service.one"), api("sample.Service.two", "(int)")]
        analyzer = [{**row, "analysis_status": "reachable"} for row in universe]
        oracle = [oracle_record(row) for row in universe]

        result = dual.reconcile_accuracy_lines(
            universe,
            analyzer,
            oracle,
            expected_artifact_sha256=ARTIFACT_SHA256,
        )

        self.assertFalse(result["blocking"], result)
        self.assertEqual(result["selected"], 2)
        self.assertEqual(result["verified"], 2)
        self.assertEqual(result["line_counts"], {
            "api_universe": 2,
            "analyzer": 2,
            "oracle": 2,
        })

    def test_missing_oracle_identity_blocks_instead_of_sampling(self):
        universe = [api("sample.Service.one"), api("sample.Service.two")]
        analyzer = [{**row, "analysis_status": "reachable"} for row in universe]

        result = dual.reconcile_accuracy_lines(
            universe,
            analyzer,
            [oracle_record(universe[0])],
            expected_artifact_sha256=ARTIFACT_SHA256,
        )

        self.assertTrue(result["blocking"])
        self.assertEqual(result["unverified"], 1)
        self.assertEqual(len(result["missing_identities"]), 1)

    def test_wrong_analyzer_conclusion_is_incorrect(self):
        universe = [api("sample.Service.one")]
        analyzer = [{**universe[0], "analysis_status": "uncertain"}]

        result = dual.reconcile_accuracy_lines(
            universe,
            analyzer,
            [oracle_record(universe[0], "reachable")],
            expected_artifact_sha256=ARTIFACT_SHA256,
        )

        self.assertTrue(result["blocking"])
        self.assertEqual(result["incorrect"], 1)

    def test_oracle_from_different_artifact_is_invalid(self):
        universe = [api("sample.Service.one")]
        analyzer = [{**universe[0], "analysis_status": "reachable"}]
        record = oracle_record(universe[0])
        record["artifact_sha256"] = "b" * 64

        result = dual.reconcile_accuracy_lines(
            universe,
            analyzer,
            [record],
            expected_artifact_sha256=ARTIFACT_SHA256,
        )

        self.assertTrue(result["blocking"])
        self.assertEqual(result["invalid_provenance_count"], 1)
        self.assertEqual(result["verified"], 0)

    def test_cli_accepts_only_data_files_for_a_new_project(self):
        universe = [api("new.project.Entry.call")]
        analyzer_summary = {
            "reachable_apis": [{**universe[0], "analysis_status": "reachable"}],
        }
        oracle = [oracle_record(universe[0])]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            universe_path = root / "api-universe.csv"
            oracle_path = root / "oracle.csv"
            summary_path = root / "summary.json"
            output_path = root / "accuracy.json"
            for path, rows in ((universe_path, universe), (oracle_path, oracle)):
                fields = sorted({key for row in rows for key in row})
                with path.open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(rows)
            summary_path.write_text(json.dumps(analyzer_summary), encoding="utf-8")

            with redirect_stdout(io.StringIO()):
                returncode = dual.main([
                    "--api-universe", str(universe_path),
                    "--analyzer-summary", str(summary_path),
                    "--oracle-ledger", str(oracle_path),
                    "--artifact-sha256", ARTIFACT_SHA256,
                    "--json-out", str(output_path),
                ])

            payload = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(returncode, 0)
        self.assertFalse(payload["blocking"])


if __name__ == "__main__":
    unittest.main()
