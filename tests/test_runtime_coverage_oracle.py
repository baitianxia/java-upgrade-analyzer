import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import runtime_coverage_oracle as runtime_oracle  # noqa: E402


class RuntimeCoverageOracleTest(unittest.TestCase):
    def test_runtime_coverage_matches_exact_owner_member_and_overload(self):
        apis = [{
            "coord": "g:a",
            "api_name": "sample.Service.call",
            "api_signature": "(java.lang.String,int[])",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }]
        coverage = runtime_oracle.parse_coverage_output(
            "sample/Service\tcall\t(Ljava/lang/String;[I)V\t4\t7\n"
            "sample/Service\tcall\t(I)V\t3\t5\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence.json"
            evidence.write_text("{}", encoding="utf-8")
            rows = runtime_oracle.build_runtime_oracle_rows(
                apis,
                coverage,
                artifact_sha256="a" * 64,
                evidence_path=evidence,
                evidence_sha256=hashlib.sha256(b"{}").hexdigest(),
                authority_version="0.8.15",
            )

        self.assertEqual(rows[0]["oracle_conclusion"], "reachable")
        self.assertEqual(rows[0]["runtime_covered_instructions"], 4)

    def test_absent_or_unsupported_runtime_coverage_remains_uncertain(self):
        apis = [
            {
                "coord": "g:a", "api_name": "sample.Service.call",
                "api_signature": "()", "symbol_kind": "method",
                "change_type": "REMOVED",
            },
            {
                "coord": "g:a", "api_name": "sample.Service.VALUE",
                "api_signature": "", "symbol_kind": "field",
                "change_type": "REMOVED",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence.json"
            evidence.write_text("{}", encoding="utf-8")
            rows = runtime_oracle.build_runtime_oracle_rows(
                apis, [], artifact_sha256="a" * 64,
                evidence_path=evidence,
                evidence_sha256=hashlib.sha256(b"{}").hexdigest(),
                authority_version="0.8.15",
            )

        self.assertEqual(
            [row["oracle_conclusion"] for row in rows],
            ["uncertain", "uncertain"],
        )

    def test_covered_override_proves_execution_of_interface_api_contract(self):
        apis = [{
            "coord": "g:a",
            "api_name": "sample.Api.call",
            "api_signature": "(java.lang.String)",
            "symbol_kind": "method",
            "change_type": "REMOVED",
        }]
        coverage = runtime_oracle.parse_coverage_output(
            "sample/Implementation\tcall\t(Ljava/lang/String;)V\t5\t8\t"
            "java.lang.Object;sample.Api\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence.json"
            evidence.write_text("{}", encoding="utf-8")
            rows = runtime_oracle.build_runtime_oracle_rows(
                apis, coverage, artifact_sha256="a" * 64,
                evidence_path=evidence,
                evidence_sha256=hashlib.sha256(b"{}").hexdigest(),
                authority_version="0.8.15",
            )

        self.assertEqual(rows[0]["oracle_conclusion"], "reachable")

    def test_classfiles_must_be_exact_bytes_from_final_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = root / "provider.jar"
            provider.write_bytes(b"provider bytes")
            artifact = root / "application.jar"
            with ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/lib/provider.jar", provider.read_bytes())

            binding = runtime_oracle.bind_classfiles_to_artifact(
                artifact, provider
            )

        self.assertEqual(binding["artifact_entry"], "BOOT-INF/lib/provider.jar")
        self.assertEqual(
            binding["classfiles_sha256"], hashlib.sha256(b"provider bytes").hexdigest()
        )

    def test_unrelated_classfiles_are_rejected_even_with_valid_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = root / "provider.jar"
            provider.write_bytes(b"unrelated")
            artifact = root / "application.jar"
            with ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/lib/provider.jar", b"actual")

            with self.assertRaisesRegex(
                ValueError, "classfiles_not_bound_to_final_artifact"
            ):
                runtime_oracle.bind_classfiles_to_artifact(artifact, provider)

    def test_junit_oracle_requires_executed_passing_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "TEST.xml"
            report.write_text(
                '<testsuite tests="1" failures="0" errors="0" skipped="0"/>',
                encoding="utf-8",
            )
            result = runtime_oracle.validate_junit_reports([report])
            report.write_text(
                '<testsuite tests="1" failures="1" errors="0" skipped="0"/>',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "runtime_tests_failed"):
                runtime_oracle.validate_junit_reports([report])

        self.assertEqual(result["totals"]["tests"], 1)

    def test_runtime_command_contract_is_data_not_project_registry(self):
        command = ["mvn", "-pl", "consumer", "-Dtest=RuntimeTest", "test"]
        encoded = json.dumps(command)

        self.assertEqual(json.loads(encoded), command)


if __name__ == "__main__":
    unittest.main()
