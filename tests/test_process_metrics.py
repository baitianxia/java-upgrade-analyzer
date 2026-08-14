import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import process_metrics  # noqa: E402


class ProcessMetricsTest(unittest.TestCase):
    def test_filetime_uses_full_64_bit_100_nanosecond_value(self):
        value = process_metrics.wintypes.FILETIME(10, 1)

        self.assertEqual(process_metrics._filetime_seconds(value), 429.4967306)

    def test_non_windows_platform_does_not_touch_native_windows_apis(self):
        self.assertIsNone(
            process_metrics.windows_current_process_usage("posix")
        )


if __name__ == "__main__":
    unittest.main()
