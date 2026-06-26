try:
    from .smoke_test_base import SmokeRegressionTestCase
except ImportError:  # pragma: no cover - direct unittest discovery imports as top-level module
    from smoke_test_base import SmokeRegressionTestCase


class SmokeOrchestratorTest(SmokeRegressionTestCase):
    def test_orchestrator_group(self):
        self.run_smoke_group("orchestrator")
