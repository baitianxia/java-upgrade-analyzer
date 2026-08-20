import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
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

    def test_darwin_available_memory_uses_reclaimable_vm_pages(self):
        output = """\
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                               100.
Pages active:                             900.
Pages inactive:                           200.
Pages speculative:                         30.
Pages purgeable:                           40.
Pages wired down:                         500.
"""
        with patch.object(
            process_metrics.os,
            "sysconf",
            side_effect=ValueError("not available"),
        ), patch.object(
            process_metrics,
            "run_managed_subprocess",
            return_value=SimpleNamespace(returncode=0, stdout=output),
        ) as run:
            available = process_metrics.system_available_memory_bytes(
                "darwin"
            )

        self.assertEqual(available, (100 + 200 + 30 + 40) * 16384)
        run.assert_called_once_with(
            ["/usr/bin/vm_stat"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=2.0,
            check=False,
        )

    def test_darwin_available_memory_fails_open_on_unknown_output(self):
        with patch.object(
            process_metrics.os,
            "sysconf",
            side_effect=ValueError("not available"),
        ), patch.object(
            process_metrics,
            "run_managed_subprocess",
            return_value=SimpleNamespace(returncode=0, stdout="unknown"),
        ):
            self.assertIsNone(
                process_metrics.system_available_memory_bytes("darwin")
            )


if __name__ == "__main__":
    unittest.main()
