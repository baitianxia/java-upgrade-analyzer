import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import compat  # noqa: E402
import s1_dep_diff  # noqa: E402


class BuildToolSelectionTest(unittest.TestCase):
    def test_maven_prefers_executable_project_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            wrapper = project / ("mvnw.cmd" if compat.IS_WINDOWS else "mvnw")
            wrapper.write_text("@echo off\n" if compat.IS_WINDOWS else "#!/bin/sh\n")
            if not compat.IS_WINDOWS:
                wrapper.chmod(0o755)

            command = compat.mvn_cmd(project)

        self.assertEqual(command, [str(wrapper.resolve())])

    @unittest.skipIf(compat.IS_WINDOWS, "Unix shell fallback only")
    def test_maven_uses_shell_for_non_executable_project_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            wrapper = project / "mvnw"
            wrapper.write_text("#!/bin/sh\n")
            wrapper.chmod(0o644)

            with patch.object(compat, "find_executable", return_value="/bin/sh"):
                command = compat.mvn_cmd(project)

        self.assertEqual(command, ["/bin/sh", str(wrapper.resolve())])

    def test_maven_without_project_scope_uses_analyzer_system_tool(self):
        with patch.object(compat, "find_executable", return_value="/tools/mvn"):
            command = compat.mvn_cmd()

        self.assertEqual(command, ["/tools/mvn"])

    def test_maven_project_commands_use_worktree_wrapper_without_newer_only_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            (project / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion></project>",
                encoding="utf-8",
            )
            observed_workdirs = []
            commands = []

            def fake_mvn_cmd(work_dir=None):
                observed_workdirs.append(str(Path(work_dir).resolve()))
                return ["project-mvn"]

            def fake_run(command, **_kwargs):
                commands.append(command)
                return "[INFO] org.example:demo:jar:1.0:runtime\n", "", 0

            with patch.object(s1_dep_diff, "mvn_cmd", side_effect=fake_mvn_cmd), \
                    patch.object(s1_dep_diff, "run_cmd", side_effect=fake_run):
                s1_dep_diff.collect_runtime_deps_for_workspace(project)

        self.assertEqual(observed_workdirs, [str(project.resolve())])
        self.assertNotIn("--no-transfer-progress", commands[0])


if __name__ == "__main__":
    unittest.main()
