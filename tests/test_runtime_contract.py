import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bootstrap_runtime  # noqa: E402
import runtime_contract  # noqa: E402


class RuntimeContractTest(unittest.TestCase):
    def test_requirement_parser_covers_empty_comments_and_each_invalid_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "requirements.txt"
            path.write_text("\n# comment\nalpha==1.2.3\n", encoding="utf-8")
            self.assertEqual(
                runtime_contract._load_required_packages(path),
                {"alpha": "1.2.3"},
            )

            for declaration in ("alpha", "==1.2.3", "alpha=="):
                with self.subTest(declaration=declaration):
                    path.write_text(declaration + "\n", encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "exact == pin"):
                        runtime_contract._load_required_packages(path)

            path.write_text("", encoding="utf-8")
            self.assertEqual(runtime_contract._load_required_packages(path), {})

    def test_check_and_runtime_policy_cover_default_and_failure_projections(self):
        passed = runtime_contract._check("component", True, "value", "expected")
        failed = runtime_contract._check(
            "component", False, "", "expected", "reason"
        )
        self.assertEqual((passed.status, passed.reason), ("passed", ""))
        self.assertEqual(
            (failed.status, failed.observed, failed.reason),
            ("failed", "missing", "reason"),
        )

        with patch.object(
            runtime_contract.platform,
            "python_implementation",
            return_value="CPython",
        ), patch.object(runtime_contract.sys, "version_info", (3, 14, 1)):
            self.assertTrue(runtime_contract.is_python_runtime_compatible())
            self.assertIsNone(runtime_contract.python_runtime_warning())

        self.assertIsNone(
            runtime_contract.python_runtime_warning("PyPy", (3, 14), "3.14")
        )
        self.assertIsNone(
            runtime_contract.python_runtime_warning("CPython", (3, 9), "3.9")
        )
        warning = runtime_contract.python_runtime_warning("CPython", (3, 15))
        self.assertIn("CPython", warning["observed"])

    def test_command_probe_covers_missing_failure_and_combined_output(self):
        with patch.object(runtime_contract, "find_executable", return_value=None), \
                patch.object(runtime_contract, "run_cmd") as run:
            self.assertEqual(runtime_contract._run(["missing"]), (None, ""))
            run.assert_not_called()

        for result, expected in (
            ((" stdout ", " stderr ", 0), (True, "stdout\nstderr")),
            (("", " failure ", 7), (False, "failure")),
            (("", "", 0), (True, "")),
        ):
            with self.subTest(result=result), patch.object(
                runtime_contract, "find_executable", return_value="/tool"
            ), patch.object(runtime_contract, "run_cmd", return_value=result):
                self.assertEqual(runtime_contract._run(["tool", "--version"]), expected)

    def test_version_parsers_cover_absent_partial_fallback_and_legacy_shapes(self):
        cases = (
            ("", ()),
            ("version 21", (21, 0, 0)),
            ("version 17.0", (17, 0, 0)),
            ("version 8.0.402", (8, 0, 402)),
        )
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(runtime_contract._version_tuple(text), expected)

        jdk_cases = (
            (None, None),
            ("no version here", None),
            ("noise 8 then 21.0.2", 21),
            ('java version "1"', None),
            ("jdeps 17", 17),
        )
        for text, expected in jdk_cases:
            with self.subTest(text=text):
                self.assertEqual(runtime_contract._jdk_major(text), expected)

    def test_runtime_validation_reports_every_dependency_and_tool_failure_class(self):
        def missing_distribution(_name):
            raise runtime_contract.metadata.PackageNotFoundError

        def failed_command(command, timeout=15):
            del timeout
            return False, "" if command[0] == "git" else f"{command[0]} failed"

        with patch.object(runtime_contract, "_run", side_effect=failed_command), \
                patch.object(runtime_contract, "mvn_cmd", return_value=["mvn"]), \
                patch.object(runtime_contract, "gradle_cmd", return_value=["gradle"]), \
                patch.object(runtime_contract.metadata, "version", side_effect=missing_distribution), \
                patch.object(runtime_contract.importlib, "import_module", side_effect=ImportError("missing parser")), \
                patch.object(runtime_contract.platform, "python_implementation", return_value="PyPy"), \
                patch.object(runtime_contract.platform, "python_version", return_value="3.14.0"), \
                patch.object(runtime_contract.platform, "system", return_value="Plan9"), \
                patch.object(runtime_contract.sys, "version_info", (3, 14, 0)):
            checks = runtime_contract.validate_runtime_contract(
                require_java_tools=True,
                require_maven=True,
                require_gradle=True,
                project_dir="/project",
            )

        by_component = {item.component: item for item in checks}
        self.assertEqual(by_component["python"].reason, "unsupported_python_implementation; use CPython")
        self.assertEqual(by_component["platform"].reason, "unsupported_platform")
        self.assertTrue(all(
            by_component[f"python_package:{name}"].status == "failed"
            for name in runtime_contract.REQUIRED_PACKAGES
        ))
        self.assertTrue(all(
            by_component[f"python_import:{name}"].status == "failed"
            for name in ("tree_sitter", "tree_sitter_java")
        ))
        self.assertTrue(all(
            by_component[f"tool:{name}"].status == "failed"
            for name in ("git", "java", "javac", "javap", "jdeps", "mvn", "gradle")
        ))

        with patch.object(runtime_contract, "_run", return_value=(True, "git ok")), \
                patch.object(runtime_contract.metadata, "version", side_effect=lambda name: runtime_contract.REQUIRED_PACKAGES[name]), \
                patch.object(runtime_contract.importlib, "import_module", return_value=object()), \
                patch.object(runtime_contract.platform, "python_implementation", return_value="CPython"), \
                patch.object(runtime_contract.platform, "python_version", return_value="3.9.9"), \
                patch.object(runtime_contract.platform, "system", return_value="Linux"), \
                patch.object(runtime_contract.sys, "version_info", (3, 9, 9)):
            below_minimum = runtime_contract.validate_runtime_contract()
        self.assertEqual(
            below_minimum[0].reason,
            "python_below_minimum; use CPython 3.10 or newer",
        )

    def test_contract_payload_failure_has_no_spurious_warning(self):
        failed = runtime_contract.ContractCheck(
            component="tool:git",
            status="failed",
            observed="missing",
            expected="installed",
            reason="missing",
        )
        with patch.object(
            runtime_contract,
            "validate_runtime_contract",
            return_value=[failed],
        ), patch.object(
            runtime_contract,
            "python_runtime_warning",
            return_value=None,
        ):
            payload = runtime_contract.contract_payload()

        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["warnings"], [])

    def test_python_policy_separates_minimum_from_ci_verified_matrix(self):
        self.assertEqual(runtime_contract.MINIMUM_PYTHON, (3, 10))
        self.assertEqual(
            runtime_contract.CI_VERIFIED_PYTHON,
            {(3, 12), (3, 13), (3, 14)},
        )

    def test_python_policy_accepts_unverified_minor_above_minimum(self):
        self.assertTrue(
            runtime_contract.is_python_runtime_compatible("CPython", (3, 11))
        )
        warning = runtime_contract.python_runtime_warning(
            "CPython",
            (3, 11),
            "3.11.9",
        )
        self.assertIsNotNone(warning)
        self.assertEqual(warning["reason"], "python_version_not_ci_verified")

    def test_python_policy_rejects_below_minimum_and_unverified_implementation(self):
        self.assertFalse(
            runtime_contract.is_python_runtime_compatible("CPython", (3, 9))
        )
        self.assertFalse(
            runtime_contract.is_python_runtime_compatible("PyPy", (3, 14))
        )

    def test_contract_payload_reports_unverified_minor_as_nonblocking_warning(self):
        with patch.object(runtime_contract, "_run", return_value=(True, "git version 2.45.0")), \
                patch.object(runtime_contract.metadata, "version", side_effect=lambda name: runtime_contract.REQUIRED_PACKAGES[name]), \
                patch.object(runtime_contract.importlib, "import_module", return_value=object()), \
                patch.object(runtime_contract.platform, "python_implementation", return_value="CPython"), \
                patch.object(runtime_contract.platform, "python_version", return_value="3.11.9"), \
                patch.object(runtime_contract.platform, "system", return_value="Linux"), \
                patch.object(runtime_contract.sys, "version_info", (3, 11, 9)):
            payload = runtime_contract.contract_payload()

        self.assertEqual(payload["status"], "passed")
        self.assertEqual(len(payload["warnings"]), 1)
        self.assertEqual(
            payload["warnings"][0]["reason"],
            "python_version_not_ci_verified",
        )

    def test_runtime_requirements_are_exactly_pinned(self):
        declared = {
            line.strip() for line in
            (ROOT / "requirements-runtime.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        self.assertEqual(declared, {
            "tree-sitter==0.25.2",
            "tree-sitter-java==0.23.5",
        })

    def test_offline_bootstrap_disables_package_index(self):
        command = bootstrap_runtime.build_command("/tmp/wheels")
        self.assertIn("--no-index", command)
        self.assertIn("--find-links", command)
        self.assertIn("--requirement", command)

    def test_bootstrap_accepts_unverified_minor_and_prints_warning(self):
        stdout = StringIO()
        stderr = StringIO()
        with patch.object(bootstrap_runtime.platform, "python_implementation", return_value="CPython"), \
                patch.object(bootstrap_runtime.platform, "python_version", return_value="3.11.9"), \
                patch.object(bootstrap_runtime.sys, "version_info", (3, 11, 9)), \
                patch.object(bootstrap_runtime.sys, "version", "3.11.9 (test)"), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            returncode = bootstrap_runtime.main(["--dry-run"])

        self.assertEqual(returncode, 0)
        self.assertIn("pip install", stdout.getvalue())
        self.assertIn("not in the CI-verified Python matrix", stderr.getvalue())

    def test_bootstrap_rejects_python_below_minimum(self):
        stderr = StringIO()
        with patch.object(bootstrap_runtime.platform, "python_implementation", return_value="CPython"), \
                patch.object(bootstrap_runtime.sys, "version_info", (3, 9, 19)), \
                patch.object(bootstrap_runtime.sys, "version", "3.9.19 (test)"), \
                redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            bootstrap_runtime.main(["--dry-run"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("CPython 3.10 or newer", stderr.getvalue())

    def test_jdk_major_supports_legacy_and_modern_version_formats(self):
        self.assertEqual(runtime_contract._jdk_major('java version "1.8.0_402"'), 8)
        self.assertEqual(runtime_contract._jdk_major('openjdk version "21.0.2"'), 21)
        self.assertEqual(
            runtime_contract._jdk_major(
                "Picked up JAVA_TOOL_OPTIONS: -Dfile.encoding=UTF-8\njavac 17.0.12"
            ),
            17,
        )

    def test_contract_accepts_project_selected_legacy_java_and_maven(self):
        outputs = {
            "git": "git version 2.45.0",
            "java": 'java version "1.8.0_402"',
            "javac": "javac 1.8.0_402",
            "javap": "1.8.0_402",
            "jdeps": "1.8.0_402",
            "mvn": (
                "Apache Maven 3.1.1\n"
                "Java version: 1.8.0_402, vendor: Example"
            ),
        }

        def fake_run(command, timeout=15):
            return True, outputs[command[0]]

        with patch.object(runtime_contract, "_run", side_effect=fake_run), \
                patch.object(runtime_contract, "mvn_cmd", return_value=["mvn"]), \
                patch.object(runtime_contract.metadata, "version", side_effect=lambda name: runtime_contract.REQUIRED_PACKAGES[name]), \
                patch.object(runtime_contract.importlib, "import_module", return_value=object()), \
                patch.object(runtime_contract.platform, "system", return_value="Linux"), \
                patch.object(runtime_contract.sys, "version_info", (3, 12, 1)):
            checks = runtime_contract.validate_runtime_contract(
                require_java_tools=True,
                require_maven=True,
            )

        self.assertTrue(all(item.status == "passed" for item in checks), checks)
        self.assertFalse(hasattr(runtime_contract, "MINIMUM_MAVEN"))
        self.assertFalse(hasattr(runtime_contract, "SUPPORTED_JDK_MAJORS"))

    def test_gradle_contract_accepts_project_wrapper_without_version_floor(self):
        outputs = {
            "git": "git version 2.45.0",
            "/project/gradlew": "Gradle 6.0.1\nJVM: 1.8.0_402 (Example)",
        }

        def fake_run(command, timeout=15):
            return True, outputs[command[0]]

        with patch.object(runtime_contract, "_run", side_effect=fake_run), \
                patch.object(runtime_contract, "gradle_cmd", return_value=["/project/gradlew"]), \
                patch.object(runtime_contract.metadata, "version", side_effect=lambda name: runtime_contract.REQUIRED_PACKAGES[name]), \
                patch.object(runtime_contract.importlib, "import_module", return_value=object()), \
                patch.object(runtime_contract.platform, "system", return_value="Linux"), \
                patch.object(runtime_contract.sys, "version_info", (3, 12, 1)):
            checks = runtime_contract.validate_runtime_contract(
                require_maven=False,
                require_gradle=True,
                project_dir="/project",
            )

        self.assertTrue(all(item.status == "passed" for item in checks), checks)
        self.assertFalse(hasattr(runtime_contract, "MINIMUM_GRADLE"))

    def test_default_analyzer_preflight_does_not_probe_project_toolchains(self):
        commands = []

        def fake_run(command, timeout=15):
            commands.append(command)
            return True, "git version 2.45.0"

        with patch.object(runtime_contract, "_run", side_effect=fake_run), \
                patch.object(runtime_contract.metadata, "version", side_effect=lambda name: runtime_contract.REQUIRED_PACKAGES[name]), \
                patch.object(runtime_contract.importlib, "import_module", return_value=object()), \
                patch.object(runtime_contract.platform, "system", return_value="Linux"), \
                patch.object(runtime_contract.sys, "version_info", (3, 12, 1)):
            checks = runtime_contract.validate_runtime_contract()

        self.assertTrue(all(item.status == "passed" for item in checks), checks)
        self.assertEqual(commands, [["git", "--version"]])

    def test_formal_runner_preflight_does_not_select_project_build_tools(self):
        source = (ROOT / "scripts" / "run_step.py").read_text(encoding="utf-8")
        runner_start = source.index("def _main_with_workflow_lock_held(")
        runner_end = source.index("\ndef main(", runner_start)
        main_source = source[runner_start:runner_end]
        self.assertIn("contract_payload()", main_source)
        preflight = main_source[:main_source.index("load_main_state(report_dir")]
        self.assertNotIn("require_maven=True", preflight)
        self.assertNotIn("require_gradle=True", preflight)


if __name__ == "__main__":
    unittest.main()
