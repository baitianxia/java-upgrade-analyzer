import sys
import unittest
from pathlib import Path
from unittest.mock import patch


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

    def test_available_memory_uses_available_pages_not_total_pages(self):
        values = {
            "SC_AVPHYS_PAGES": 123,
            "SC_PAGE_SIZE": 4096,
        }
        with patch.object(
            process_metrics.os,
            "sysconf",
            side_effect=lambda name: values[name],
        ):
            available = process_metrics.system_available_memory_bytes("posix")

        self.assertEqual(available, 123 * 4096)


if __name__ == "__main__":
    unittest.main()
