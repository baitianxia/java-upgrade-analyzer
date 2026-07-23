import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "quality_gate", ROOT / "scripts" / "quality_gate.py"
)
quality_gate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(quality_gate)

GIT_CHECK_SPEC = importlib.util.spec_from_file_location(
    "git_change_check", ROOT / "scripts" / "git_change_check.py"
)
git_change_check = importlib.util.module_from_spec(GIT_CHECK_SPEC)
assert GIT_CHECK_SPEC.loader is not None
GIT_CHECK_SPEC.loader.exec_module(git_change_check)


class CiQualityContractTest(unittest.TestCase):
    def test_smoke_workflow_covers_behavior_paths_and_explicit_java_tools(self):
        text = (ROOT / ".github/workflows/smoke-regression.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('"references/**"', text)
        self.assertIn("actions/setup-java@", text)
        self.assertIn("mvn -version", text)
        self.assertIn("--profile step5", text)
        self.assertIn("--json-out", text)

    def test_release_workflow_is_scheduled_manual_and_runs_guard_release_gate(self):
        path = ROOT / ".github/workflows/release-regression.yml"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")

        self.assertIn("schedule:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("actions/setup-java@", text)
        self.assertIn("--profile release", text)
        self.assertIn("--include-real", text)
        self.assertIn("--continue-on-failure", text)
        self.assertIn("--json-out", text)
        self.assertIn("materialize_real_project_asset.py", text)
        self.assertIn("--selector guard --declared-locations", text)
        self.assertIn("--real-case guard", text)
        self.assertNotIn("--real-case commons-text", text)

    def test_ci_layers_quick_on_pr_step5_on_main_and_full_guard_on_schedule(self):
        smoke = (ROOT / ".github/workflows/smoke-regression.yml").read_text(
            encoding="utf-8"
        )
        release = (ROOT / ".github/workflows/release-regression.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("pull_request:", smoke)
        self.assertIn("quick-regression:", smoke)
        self.assertIn("--profile quick", smoke)
        self.assertIn("github.ref == 'refs/heads/main'", smoke)
        self.assertIn("--profile step5", smoke)
        self.assertIn('python: ["3.12", "3.13", "3.14"]', smoke)
        self.assertIn("python-version: ${{ matrix.python }}", smoke)
        self.assertIn("schedule:", release)
        self.assertIn("--profile release", release)
        self.assertIn("--include-real --real-case guard", release)

    def test_release_workflow_runs_artifact_matrix_on_multiple_jdks(self):
        text = (ROOT / ".github/workflows/release-regression.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("artifact-topology-matrix:", text)
        self.assertIn("java: [\"11\", \"17\", \"21\"]", text)
        self.assertIn("java-version: ${{ matrix.java }}", text)
        self.assertIn("tests.test_runtime_topology_matrix", text)
        self.assertIn("tests.test_artifact_bytecode_catalog", text)

    def test_platform_contract_covers_pr_and_main_on_supported_os_jdk_matrix(self):
        text = (ROOT / ".github/workflows/platform-contract.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("pull_request:", text)
        self.assertIn('- "main"', text)
        self.assertIn("os: [ubuntu-latest, macos-latest, windows-latest]", text)
        self.assertIn('java: ["11", "17", "21"]', text)
        self.assertIn("python-version: \"3.12\"", text)

    def test_every_gate_profile_starts_with_environment_contract(self):
        for profile in ("quick", "step5", "release"):
            with self.subTest(profile=profile):
                plan = quality_gate.build_plan(profile, skip_real=True)
                self.assertEqual(plan[0].name, "environment_contract")

    def test_every_gate_profile_runs_platform_compatibility_after_compile(self):
        for profile in ("quick", "step5", "release"):
            with self.subTest(profile=profile):
                plan = quality_gate.build_plan(profile, skip_real=True)
                names = [task.name for task in plan]

                self.assertIn("platform_compatibility", names)
                self.assertGreater(
                    names.index("platform_compatibility"),
                    names.index("py_compile_scripts"),
                )

    def test_tool_preflight_matches_profile_dependencies(self):
        quick = quality_gate.build_plan("quick", skip_real=True)[0]
        step5 = quality_gate.build_plan("step5", skip_real=True)[0]

        self.assertEqual(quick.command, ["without_maven"])
        self.assertEqual(step5.command, ["with_maven"])

    def test_release_diff_check_includes_committed_branch_changes(self):
        task = next(
            item for item in quality_gate.build_plan("release", skip_real=True)
            if item.name == "git_diff_check"
        )

        self.assertEqual(task.command[-1], "scripts/git_change_check.py")
        release = (ROOT / ".github/workflows/release-regression.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("fetch-depth: 0", release)

    def test_git_change_check_prefers_github_base_branch(self):
        def fake_git(*args):
            candidate = args[-1]
            return type("Result", (), {
                "returncode": 0 if candidate == "origin/release" else 1,
                "stdout": "feature\n" if args[:2] == ("branch", "--show-current") else "",
            })()

        with patch.dict(git_change_check.os.environ, {"GITHUB_BASE_REF": "release"}), \
                patch.object(git_change_check, "_git", side_effect=fake_git):
            self.assertEqual(git_change_check.comparison_base(), "origin/release")

    def test_git_change_check_uses_previous_commit_on_main(self):
        def fake_git(*args):
            if args[:2] == ("branch", "--show-current"):
                return type("Result", (), {"returncode": 0, "stdout": "main\n"})()
            return type("Result", (), {
                "returncode": 0 if args[-1] == "HEAD^" else 1,
                "stdout": "",
            })()

        with patch.dict(git_change_check.os.environ, {}, clear=True), \
                patch.object(git_change_check, "_git", side_effect=fake_git):
            self.assertEqual(git_change_check.comparison_base(), "HEAD^")

    def test_environment_preflight_fails_instead_of_skipping(self):
        task = quality_gate._environment_contract_task()
        with patch.object(
            quality_gate,
            "contract_payload",
            return_value={
                "status": "failed",
                "checks": [{
                    "component": "tool:javap", "status": "failed",
                    "observed": "missing", "expected": "executable",
                    "reason": "tool_missing_or_not_executable",
                }],
            },
        ):
            result = quality_gate._run_environment_contract_task(task)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.returncode, 1)
        self.assertIn("javap", result.purpose)


if __name__ == "__main__":
    unittest.main()
