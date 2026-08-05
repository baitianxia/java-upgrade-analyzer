import sys
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
        main_source = source[source.index("def main("):]
        self.assertIn("contract_payload()", main_source)
        preflight = main_source[:main_source.index("load_main_state(report_dir")]
        self.assertNotIn("require_maven=True", preflight)
        self.assertNotIn("require_gradle=True", preflight)


if __name__ == "__main__":
    unittest.main()
