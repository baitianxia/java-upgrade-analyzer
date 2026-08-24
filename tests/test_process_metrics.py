import sys
import unittest
import ctypes
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


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
        with patch.object(process_metrics.sys, "platform", "linux"):
            self.assertIsNone(process_metrics.windows_current_process_usage())

    def test_windows_usage_reads_native_cpu_and_peak_memory_values(self):
        def populate_times(_handle, _creation, _exit_time, kernel, user):
            kernel._obj.dwLowDateTime = 20_000_000
            kernel._obj.dwHighDateTime = 0
            user._obj.dwLowDateTime = 10_000_000
            user._obj.dwHighDateTime = 0
            return 1

        def populate_memory(_handle, memory, _size):
            memory._obj.peak_working_set_size = 123_456
            return 1

        kernel32 = SimpleNamespace(
            GetCurrentProcess=MagicMock(return_value=99),
            GetProcessTimes=MagicMock(side_effect=populate_times),
        )
        psapi = SimpleNamespace(
            GetProcessMemoryInfo=MagicMock(side_effect=populate_memory),
        )

        with patch.object(
            ctypes,
            "WinDLL",
            side_effect=lambda name, **_kwargs: (
                kernel32 if name == "kernel32" else psapi
            ),
            create=True,
        ):
            usage = process_metrics.windows_current_process_usage("win32")

        self.assertEqual(usage.user_seconds, 1.0)
        self.assertEqual(usage.system_seconds, 2.0)
        self.assertEqual(usage.peak_rss_bytes, 123_456)

    def test_windows_usage_propagates_each_native_api_failure(self):
        failure = RuntimeError("native API failed")
        for time_result, memory_result in ((0, 1), (1, 0)):
            kernel32 = SimpleNamespace(
                GetCurrentProcess=MagicMock(return_value=99),
                GetProcessTimes=MagicMock(return_value=time_result),
            )
            psapi = SimpleNamespace(
                GetProcessMemoryInfo=MagicMock(return_value=memory_result),
            )
            with self.subTest(
                time_result=time_result,
                memory_result=memory_result,
            ), patch.object(
                ctypes,
                "WinDLL",
                side_effect=lambda name, **_kwargs: (
                    kernel32 if name == "kernel32" else psapi
                ),
                create=True,
            ), patch.object(
                ctypes,
                "WinError",
                return_value=failure,
                create=True,
            ), patch.object(
                ctypes,
                "get_last_error",
                return_value=5,
                create=True,
            ), self.assertRaisesRegex(RuntimeError, "native API failed"):
                process_metrics.windows_current_process_usage("windows")

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

        with patch.object(process_metrics.sys, "platform", "linux"), patch.object(
            process_metrics.os,
            "sysconf",
            side_effect=lambda name: values[name],
        ):
            self.assertEqual(
                process_metrics.system_available_memory_bytes(),
                123 * 4096,
            )

    def test_available_memory_covers_windows_failures_and_posix_invalid_values(self):
        def populate_status(status):
            status._obj.ullAvailPhys = 987_654
            return 1

        for result, expected_error in ((populate_status, False), (0, True)):
            kernel32 = SimpleNamespace(
                GlobalMemoryStatusEx=MagicMock(side_effect=result)
                if callable(result)
                else MagicMock(return_value=result),
            )
            context = (
                self.assertRaisesRegex(RuntimeError, "native memory failed")
                if expected_error
                else nullcontext()
            )
            with self.subTest(result=result), patch.object(
                ctypes,
                "WinDLL",
                return_value=kernel32,
                create=True,
            ), patch.object(
                ctypes,
                "WinError",
                return_value=RuntimeError("native memory failed"),
                create=True,
            ), patch.object(
                ctypes,
                "get_last_error",
                return_value=5,
                create=True,
            ), context:
                value = process_metrics.system_available_memory_bytes("nt")
                if not expected_error:
                    self.assertEqual(value, 987_654)

        for pages, page_size in ((-1, 4096), (1, 0)):
            values = {
                "SC_AVPHYS_PAGES": pages,
                "SC_PAGE_SIZE": page_size,
            }
            with self.subTest(
                pages=pages,
                page_size=page_size,
            ), patch.object(
                process_metrics.os,
                "sysconf",
                side_effect=lambda name: values[name],
            ):
                self.assertIsNone(
                    process_metrics.system_available_memory_bytes("posix")
                )

        with patch.object(
            process_metrics.os,
            "sysconf",
            side_effect=OSError("unsupported"),
        ), patch.object(process_metrics, "_darwin_available_memory_bytes") as darwin:
            self.assertIsNone(
                process_metrics.system_available_memory_bytes("freebsd")
            )
            darwin.assert_not_called()

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

    def test_darwin_probe_covers_command_and_output_boundary_failures(self):
        probes = (
            OSError("cannot execute"),
            SimpleNamespace(returncode=2, stdout=""),
            SimpleNamespace(
                returncode=0,
                stdout="page size of 0 bytes\nPages free: 1.\n",
            ),
            SimpleNamespace(returncode=0, stdout="page size of 4096 bytes\n"),
        )
        for probe in probes:
            with self.subTest(probe=repr(probe)), patch.object(
                process_metrics,
                "run_managed_subprocess",
                side_effect=probe if isinstance(probe, BaseException) else None,
                return_value=None if isinstance(probe, BaseException) else probe,
            ):
                self.assertIsNone(process_metrics._darwin_available_memory_bytes())

        with patch.object(
            process_metrics,
            "run_managed_subprocess",
            return_value=SimpleNamespace(
                returncode=0,
                stdout="page size of 4096 bytes\nPages free: 2.\n",
            ),
        ):
            self.assertEqual(
                process_metrics._darwin_available_memory_bytes(),
                2 * 4096,
            )


if __name__ == "__main__":
    unittest.main()
