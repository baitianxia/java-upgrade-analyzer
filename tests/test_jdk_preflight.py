import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from jdk_preflight import (  # noqa: E402
    JdkPreflightError,
    jdk_tool_path,
    preflight_jdk_home,
)


def current_jdk_home():
    java = shutil.which("java")
    if not java:
        return None
    completed = subprocess.run(
        [java, "-XshowSettings:properties", "-version"],
        capture_output=True,
        text=True,
        check=False,
    )
    match = re.search(
        r"^\s*java\.home\s*=\s*(.+)$", completed.stderr, re.MULTILINE,
    )
    return Path(match.group(1).strip()).resolve() if match else None


class JdkPreflightTest(unittest.TestCase):
    def test_full_jdk_probe_compiles_disassembles_and_executes(self):
        home = current_jdk_home()
        if (
            home is None
            or not (home / "jmods").is_dir()
            or not jdk_tool_path(home, "javac").is_file()
            or not jdk_tool_path(home, "javap").is_file()
        ):
            self.skipTest("full JDK required")

        result = preflight_jdk_home(home)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["probe"], "compile-javap-execute-v1")
        self.assertEqual(set(result["tools"]), {"java", "javac", "javap"})
        self.assertTrue(result["jdk_preflight_identity"])
        self.assertTrue(result["platform"]["content"])

    def test_missing_javap_is_rejected_before_long_running_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "jdk"
            (home / "bin").mkdir(parents=True)
            (home / "lib").mkdir()
            (home / "jmods").mkdir()
            (home / "release").write_text(
                'JAVA_VERSION="17.0.1"\n', encoding="utf-8",
            )
            (home / "lib" / "modules").write_bytes(b"modules")
            (home / "jmods" / "java.base.jmod").write_bytes(b"jmod")
            for name in ("java", "javac"):
                (home / "bin" / name).write_text("tool", encoding="utf-8")

            with self.assertRaises(JdkPreflightError) as raised:
                preflight_jdk_home(home)

        self.assertEqual(raised.exception.reason_code, "JDK_REQUIRED_TOOL_MISSING")
        self.assertIn("javap", str(raised.exception))

    def test_tool_resolution_accepts_windows_executable_spelling(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "bin").mkdir()
            expected = home / "bin" / "javap.exe"
            expected.write_bytes(b"launcher")

            resolved = jdk_tool_path(home, "javap")

        self.assertEqual(resolved, expected.resolve())


if __name__ == "__main__":
    unittest.main()
