import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from production_mutation import MutationSpec, run_mutant, validate_mutation_spec  # noqa: E402


class ProductionMutationTest(unittest.TestCase):
    def _repo(self, root: Path, source="def enabled():\n    return True\n") -> Path:
        repo = root / "repo"
        (repo / "scripts").mkdir(parents=True)
        (repo / "tests").mkdir()
        (repo / "scripts" / "subject.py").write_text(source, encoding="utf-8")
        (repo / "tests" / "__init__.py").write_text("", encoding="utf-8")
        (repo / "tests" / "test_subject.py").write_text(
            "import sys, unittest\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))\n"
            "from subject import enabled\n"
            "class SubjectTest(unittest.TestCase):\n"
            "    def test_enabled(self): self.assertTrue(enabled())\n",
            encoding="utf-8",
        )
        return repo

    def _spec(self, replacement="return False", function="enabled"):
        return MutationSpec(
            id="invert_enabled",
            category="ownership_inversion",
            module="scripts/subject.py",
            selector={"function": function, "node_type": "Return", "occurrence": 1},
            replacement=replacement,
            required_tests=("tests.test_subject.SubjectTest.test_enabled",),
        )

    def test_failed_regression_kills_mutant_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_mutant(self._repo(root), self._spec(), root / "runs", 30)

            self.assertEqual(result.status, "killed")
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(Path(result.diff_path).is_file())
            self.assertTrue(Path(result.log_path).is_file())

    def test_passing_regression_marks_mutant_survived(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_mutant(
                self._repo(root), self._spec("return True"), root / "runs", 30
            )

        self.assertEqual(result.status, "survived")
        self.assertEqual(result.returncode, 0)

    def test_zero_and_multiple_ast_matches_are_infrastructure_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self._repo(
                root,
                "def enabled():\n    return True\n"
                "class Nested:\n    def enabled(self):\n        return True\n",
            )
            zero = run_mutant(repo, self._spec(function="missing"), root / "zero", 30)
            multiple = run_mutant(repo, self._spec(), root / "multiple", 30)

        self.assertEqual(zero.status, "infrastructure_failed")
        self.assertIn("selector_match_count:0", zero.error)
        self.assertEqual(multiple.status, "infrastructure_failed")
        self.assertIn("selector_match_count:2", multiple.error)

    def test_command_arguments_are_not_shell_evaluated(self):
        with tempfile.TemporaryDirectory(prefix="jua mutation ; ") as tmp:
            root = Path(tmp)
            result = run_mutant(self._repo(root), self._spec(), root / "runs", 30)

        self.assertEqual(result.status, "killed")
        self.assertEqual(result.command[1:4], ("-m", "unittest", "-v"))

    def test_registered_production_mutations_have_unique_ast_selectors(self):
        import json

        payload = json.loads(
            (ROOT / "tests" / "fixtures" / "production_mutations.json").read_text(
                encoding="utf-8"
            )
        )
        specs = [MutationSpec.from_dict(row) for row in payload["mutations"]]

        self.assertEqual(
            {spec.category for spec in specs},
            {
                "edge_emission_removal",
                "ownership_inversion",
                "evidence_failure_suppression",
                "descriptor_coordinate_drop",
                "signature_identity_drop",
                "change_identity_drop",
                "uncertainty_promotion",
                "artifact_binding_bypass",
                "depth_budget_bypass",
                "fail_closed_bypass",
                "archive_skip",
            },
        )
        self.assertEqual(
            [validate_mutation_spec(ROOT, spec) for spec in specs],
            [""] * len(specs),
        )

    def test_registered_production_mutants_are_all_killed(self):
        import json

        payload = json.loads(
            (ROOT / "tests" / "fixtures" / "production_mutations.json").read_text(
                encoding="utf-8"
            )
        )
        specs = [MutationSpec.from_dict(row) for row in payload["mutations"]]
        with tempfile.TemporaryDirectory() as tmp:
            report_root = Path(tmp)
            results = [run_mutant(ROOT, spec, report_root, 120) for spec in specs]

            failures = [
                (result.mutation_id, result.status, result.error, result.log_path)
                for result in results
                if result.status != "killed"
            ]
            self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
