try:
    from .smoke_test_base import SmokeRegressionTestCase
except ImportError:  # pragma: no cover - direct unittest discovery imports as top-level module
    from smoke_test_base import SmokeRegressionTestCase


class SmokeStep5Test(SmokeRegressionTestCase):
    def test_step5_group(self):
        self.run_smoke_group("step5")
