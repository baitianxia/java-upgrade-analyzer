import ast
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analysis_contract  # noqa: E402
import artifact_alignment  # noqa: E402
import dependency_source_alignment  # noqa: E402
import real_project_regression  # noqa: E402
import topology_coverage  # noqa: E402


class GitBoundaryAdoptionTest(unittest.TestCase):
    def _git(self, repository, *args):
        result = subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def test_analysis_paths_ignore_inherited_repository_routing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            self._git(repository, "init", "-q")
            self._git(repository, "config", "user.email", "test@example.invalid")
            self._git(repository, "config", "user.name", "Git Boundary Test")
            source = repository / "src" / "App.java"
            source.parent.mkdir()
            source.write_text("class App {}\n", encoding="utf-8")
            artifact = repository / "app.jar"
            artifact.write_bytes(b"artifact")
            self._git(repository, "add", ".")
            self._git(repository, "commit", "-qm", "fixture")
            expected_revision = self._git(repository, "rev-parse", "HEAD")

            foreign = root / "foreign"
            foreign.mkdir()
            self._git(foreign, "init", "-q")
            polluted_environment = {
                "GIT_DIR": str(foreign / ".git"),
                "GIT_WORK_TREE": str(foreign),
                "GIT_INDEX_FILE": str(foreign / ".git" / "index"),
            }
            with patch.dict(os.environ, polluted_environment, clear=False):
                self.assertEqual(
                    analysis_contract.git_revision(repository), expected_revision,
                )
                fingerprint = dependency_source_alignment.repository_fingerprint(
                    repository,
                )
                self.assertEqual(fingerprint["head"], expected_revision)
                record = artifact_alignment.build_artifact_alignment(
                    repository,
                    artifact,
                    expected_revision=expected_revision,
                    internally_built=True,
                )
                self.assertEqual(record.git_revision, expected_revision)
                health = real_project_regression.collect_project_asset_health(
                    repository,
                )
                self.assertTrue(health["valid_git_checkout"])
                self.assertEqual(health["git_revision"], expected_revision)
                self.assertEqual(
                    topology_coverage.compute_git_source_tree_sha256(
                        repository, expected_revision, "src",
                    ),
                    topology_coverage.compute_source_tree_sha256(repository / "src"),
                )

    def test_product_git_commands_do_not_bypass_shared_process_boundary(self):
        subprocess_methods = {
            "run", "Popen", "call", "check_call", "check_output",
        }

        def is_literal_git_command(node):
            if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
                return False
            executable = node.elts[0]
            return (
                isinstance(executable, ast.Constant)
                and isinstance(executable.value, str)
                and Path(executable.value).name.lower() in {"git", "git.exe"}
            )

        violations = []
        for script in sorted((ROOT / "scripts").glob("*.py")):
            # compat.py is the process boundary being enforced.
            if script.name == "compat.py":
                continue
            tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
            for scope in [tree, *(node for node in ast.walk(tree) if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef),
            ))]:
                literal_git_variables = set()
                for node in ast.walk(scope):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not scope:
                        continue
                    if isinstance(node, ast.Assign) and is_literal_git_command(node.value):
                        literal_git_variables.update(
                            target.id for target in node.targets if isinstance(target, ast.Name)
                        )
                for node in ast.walk(scope):
                    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                        continue
                    if (
                        not isinstance(node.func.value, ast.Name)
                        or node.func.value.id != "subprocess"
                        or node.func.attr not in subprocess_methods
                        or not node.args
                    ):
                        continue
                    command = node.args[0]
                    if is_literal_git_command(command) or (
                        isinstance(command, ast.Name)
                        and command.id in literal_git_variables
                    ):
                        violations.append(f"{script.relative_to(ROOT)}:{node.lineno}")

        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
