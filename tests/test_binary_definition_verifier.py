import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from binary_asm_helper import resolve_asm_jar  # noqa: E402
from binary_definition_verifier import verify_class_definitions  # noqa: E402
from binary_platform_image import JdkPlatformImage  # noqa: E402


def jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, check=False,
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            return Path(line.split("=", 1)[1].strip())
    return None


class BinaryDefinitionVerifierTest(unittest.TestCase):
    def test_legal_package_info_class_does_not_abort_definition_batch(self):
        home = jdk_home()
        if not home or not shutil.which("javac"):
            self.skipTest("full JDK required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "demo" / "package-info.java"
            source.parent.mkdir(parents=True)
            source.write_text("@Deprecated package demo;\n", encoding="utf-8")
            classes = root / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = (classes / "demo" / "package-info.class").read_bytes()
            outcomes = verify_class_definitions(
                JdkPlatformImage(home, asm_jar=resolve_asm_jar()),
                {"demo/package-info": payload},
            )
        self.assertIn(outcomes["demo/package-info"]["status"], {
            "definition_ready", "verification_failed",
        })
        self.assertEqual(set(outcomes), {"demo/package-info"})

    def test_optional_nested_class_does_not_change_outer_definition_readiness(self):
        home = jdk_home()
        if not home or not shutil.which("javac"):
            self.skipTest("full JDK required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "demo" / "Outer.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; public class Outer { "
                "public static class OptionalNested implements Missing {} } "
                "interface Missing {}\n",
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            outcomes = verify_class_definitions(
                JdkPlatformImage(home, asm_jar=resolve_asm_jar()),
                {"demo/Outer": (classes / "demo" / "Outer.class").read_bytes()},
            )
        self.assertEqual(outcomes["demo/Outer"]["status"], "definition_ready")

    def test_missing_declared_member_type_still_fails_definition_readiness(self):
        home = jdk_home()
        if not home or not shutil.which("javac"):
            self.skipTest("full JDK required")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "demo" / "UsesMissing.java"
            source.parent.mkdir(parents=True)
            source.write_text(
                "package demo; public class UsesMissing { "
                "public Missing value() { return null; } } class Missing {}\n",
                encoding="utf-8",
            )
            classes = root / "classes"
            classes.mkdir()
            completed = subprocess.run(
                ["javac", "-d", str(classes), str(source)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            outcomes = verify_class_definitions(
                JdkPlatformImage(home, asm_jar=resolve_asm_jar()),
                {
                    "demo/UsesMissing": (
                        classes / "demo" / "UsesMissing.class"
                    ).read_bytes()
                },
            )
        self.assertEqual(outcomes["demo/UsesMissing"]["status"], "verification_failed")
        self.assertEqual(
            outcomes["demo/UsesMissing"]["failure_phase"], "member_linkage"
        )


if __name__ == "__main__":
    unittest.main()
