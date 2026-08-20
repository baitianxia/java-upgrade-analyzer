import ast
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from tests.blackbox.managed_process import (
    managed_process_batch,
    managed_run,
)


def _pid_is_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(
            process_query_limited_information, False, int(pid)
        )
        if not handle:
            return False
        try:
            exit_code = wintypes.DWORD()
            return bool(
                kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            ) and exit_code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    stat = Path(f"/proc/{pid}/stat")
    if stat.is_file():
        fields = stat.read_text(encoding="utf-8").split()
        if len(fields) > 2 and fields[2] == "Z":
            return False
    return True


def _wait_until_dead(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_is_alive(pid):
            return True
        time.sleep(0.05)
    return not _pid_is_alive(pid)


class BlackboxManagedProcessTest(unittest.TestCase):
    def test_helper_is_stdlib_only_and_all_timeout_calls_use_it(self):
        blackbox_root = Path(__file__).resolve().parent
        helper_path = blackbox_root / "managed_process.py"
        helper_tree = ast.parse(helper_path.read_text(encoding="utf-8"))
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(helper_tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            str(node.module or "").split(".", 1)[0]
            for node in ast.walk(helper_tree)
            if isinstance(node, ast.ImportFrom)
            and node.module != "__future__"
        }
        self.assertTrue(imported_roots <= sys.stdlib_module_names, imported_roots)

        bypasses = []
        for source_path in sorted(blackbox_root.rglob("*.py")):
            if source_path == helper_path:
                continue
            tree = ast.parse(source_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(
                    node.func, ast.Attribute
                ):
                    continue
                if not (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                    and node.func.attr in {"run", "Popen"}
                ):
                    continue
                bypasses.append(f"{source_path.name}:{node.lineno}")
        self.assertEqual(bypasses, [])

    @staticmethod
    def _write_parent(root: Path) -> Path:
        parent = root / "parent.py"
        parent.write_text(
            """import subprocess
import sys
import time
from pathlib import Path

kwargs = {}
if sys.platform == "win32":
    kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(60)"], **kwargs
)
Path(sys.argv[1]).write_text(str(child.pid), encoding="utf-8")
time.sleep(0.1 if sys.argv[2] == "exit" else 60)
""",
            encoding="utf-8",
        )
        return parent

    def test_timeout_reaps_descendant_after_direct_parent_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = self._write_parent(root)
            child_pid_path = root / "child.pid"
            with self.assertRaises(subprocess.TimeoutExpired):
                managed_run(
                    [sys.executable, str(parent), str(child_pid_path), "exit"],
                    capture_output=True,
                    timeout=0.5,
                )

            self.assertTrue(child_pid_path.is_file())
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
            self.assertTrue(
                _wait_until_dead(child_pid),
                "timeout left a black-box descendant alive",
            )

    def test_concurrent_communicate_exceptions_reap_every_owned_tree(self):
        for error_type in (KeyboardInterrupt, OSError):
            with self.subTest(error_type=error_type.__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                parent = self._write_parent(root)
                pid_paths = [root / f"child-{index}.pid" for index in range(2)]
                processes = []
                child_pids = []
                with self.assertRaises(error_type):
                    with managed_process_batch() as batch:
                        processes = [
                            batch.start(
                                [
                                    sys.executable, str(parent), str(pid_path),
                                    "sleep",
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                            )
                            for pid_path in pid_paths
                        ]
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline and not all(
                            path.is_file() for path in pid_paths
                        ):
                            time.sleep(0.05)
                        self.assertTrue(all(path.is_file() for path in pid_paths))
                        child_pids = [
                            int(path.read_text(encoding="utf-8"))
                            for path in pid_paths
                        ]

                        def interrupted_communicate(*_args, **_kwargs):
                            raise error_type("synthetic communicate failure")

                        processes[0].communicate = interrupted_communicate
                        batch.communicate(processes[0], timeout=10)

                self.assertTrue(all(process.poll() is not None for process in processes))
                self.assertTrue(
                    all(_wait_until_dead(pid) for pid in child_pids),
                    f"{error_type.__name__} left a concurrent descendant alive",
                )


if __name__ == "__main__":
    unittest.main()
