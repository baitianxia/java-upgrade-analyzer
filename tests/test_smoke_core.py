import tempfile
from pathlib import Path

try:
    from .smoke_test_base import SmokeRegressionTestCase
except ImportError:  # pragma: no cover - direct unittest discovery imports as top-level module
    from smoke_test_base import SmokeRegressionTestCase

from scripts import smoke_regression


class SmokeCoreTest(SmokeRegressionTestCase):
    def test_fixture_exposes_windows_maven_launcher_and_explicit_local_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = smoke_regression.create_smoke_workspace(Path(tmp))
            smoke_regression.initialize_smoke_project(workspace)
            env = smoke_regression.build_smoke_dep_env(workspace)

            self.assertTrue((workspace.fake_bin / "mvn.cmd").is_file())
            self.assertEqual(
                env["MAVEN_REPO_LOCAL"],
                str(workspace.fake_home / ".m2" / "repository"),
            )

    def test_core_group(self):
        self.run_smoke_group("core")
