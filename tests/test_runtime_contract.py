import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bootstrap_runtime  # noqa: E402
import runtime_contract  # noqa: E402


class RuntimeContractTest(unittest.TestCase):
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

    def test_jdk_major_supports_legacy_and_modern_version_formats(self):
        self.assertEqual(runtime_contract._jdk_major('java version "1.8.0_402"'), 8)
        self.assertEqual(runtime_contract._jdk_major('openjdk version "21.0.2"'), 21)
        self.assertEqual(
            runtime_contract._jdk_major(
                "Picked up JAVA_TOOL_OPTIONS: -Dfile.encoding=UTF-8\njavac 17.0.12"
            ),
            17,
        )

    def test_contract_executes_tools_and_rejects_mixed_jdk(self):
        outputs = {
            "git": "git version 2.45.0",
            "java": 'openjdk version "17.0.1"',
            "javac": "javac 17.0.1",
            "javap": "21.0.1",
            "jdeps": "17.0.1",
        }

        def fake_run(command, timeout=15):
            return True, outputs[command[0]]

        with patch.object(runtime_contract, "_run", side_effect=fake_run), \
                patch.object(runtime_contract.metadata, "version", side_effect=lambda name: runtime_contract.REQUIRED_PACKAGES[name]), \
                patch.object(runtime_contract.importlib, "import_module", return_value=object()), \
                patch.object(runtime_contract.platform, "system", return_value="Linux"), \
                patch.object(runtime_contract.sys, "version_info", (3, 12, 1)):
            checks = runtime_contract.validate_runtime_contract(require_maven=False)

        toolchain = next(item for item in checks if item.component == "jdk_toolchain")
        self.assertEqual(toolchain.status, "failed")
        self.assertEqual(toolchain.reason, "unsupported_or_mixed_jdk_toolchain")

    def test_formal_runner_checks_environment_before_project_state(self):
        source = (ROOT / "scripts" / "run_step.py").read_text(encoding="utf-8")
        main_source = source[source.index("def main():"):]
        contract_call = main_source.index("contract_payload(require_maven=True)")
        state_load = main_source.index("load_main_state(report_dir")
        self.assertLess(contract_call, state_load)


if __name__ == "__main__":
    unittest.main()
