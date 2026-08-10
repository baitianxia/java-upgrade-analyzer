import json
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from binary_real_project_guard import (  # noqa: E402
    BinaryRealProjectGuardError,
    DEFAULT_MANIFEST,
    _canonicalize_zip,
    load_guard_manifest,
    materialize_case,
    resolve_asset,
    run_guard,
)
from binary_pipeline import BinaryPipelineError  # noqa: E402
from binary_tool_execution import BinaryToolResult  # noqa: E402


def jdk_home():
    completed = subprocess.run(
        ["java", "-XshowSettings:properties", "-version"],
        capture_output=True, text=True, check=False,
    )
    for line in completed.stderr.splitlines():
        if "java.home" in line and "=" in line:
            return Path(line.split("=", 1)[1].strip())
    return None


class BinaryRealProjectGuardTest(unittest.TestCase):
    def test_manifest_pins_project_revision_artifacts_and_mechanism(self):
        manifests = [
            load_guard_manifest(path) for path in sorted(DEFAULT_MANIFEST.parent.glob("*.json"))
        ]
        self.assertGreaterEqual(len(manifests), 3)
        self.assertIn(
            "spring_transaction_proxy_dispatch",
            {item["expected"].get("semantic_edge_kind") for item in manifests},
        )
        self.assertIn(
            "spring_scheduled",
            {
                (item["expected"].get("entrypoint") or {}).get("entry_kind")
                for item in manifests
            },
        )
        self.assertIn(
            "spring_message_listener",
            {
                (item["expected"].get("entrypoint") or {}).get("entry_kind")
                for item in manifests
            },
        )
        for manifest in manifests:
            self.assertEqual(len(manifest["git_revision"]), 40)
            self.assertTrue(manifest["application_coordinate"])
            for asset in manifest["assets"].values():
                self.assertEqual(len(asset["sha256"]), 64)
                if asset.get("kind") == "source_build":
                    self.assertTrue(asset["repository_url"].startswith("https://"))
                    self.assertEqual(asset["git_revision"], manifest["git_revision"])
                    self.assertTrue(asset["build_command"])
                else:
                    self.assertTrue(asset["url"].startswith("https://repo1.maven.org/"))

    def test_source_build_archive_canonicalization_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.jar"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("z.txt", b"z")
                archive.writestr("a.txt", b"a")
            first = root / "first.jar"
            second = root / "second.jar"
            _canonicalize_zip(source, first)
            _canonicalize_zip(source, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_business_class_materialization_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base.jar"
            base.write_bytes(b"base-dependency")
            current_bytes = b"current-dependency"
            application = root / "application.jar"
            with zipfile.ZipFile(application, "w") as archive:
                archive.writestr("BOOT-INF/classes/demo/App.class", b"class-bytes")
                archive.writestr("BOOT-INF/classes/application.properties", b"a=1\n")
                archive.writestr("BOOT-INF/lib/dep-2.jar", current_bytes)
            application_sha = hashlib.sha256(application.read_bytes()).hexdigest()
            manifest = {
                "case": "deterministic-materialization",
                "git_revision": "1" * 40,
                "application_coordinate": "com.acme:app:1",
                "activated_frameworks": ["spring_boot"],
                "assets": {
                    "application": {"sha256": application_sha},
                    "base_dependency": {
                        "sha256": hashlib.sha256(base.read_bytes()).hexdigest(),
                        "coordinate": "com.acme:dep:1",
                    },
                },
                "current_nested_asset": {
                    "entry": "BOOT-INF/lib/dep-2.jar",
                    "coordinate": "com.acme:dep:2",
                    "sha256": hashlib.sha256(current_bytes).hexdigest(),
                },
                "entrypoint": {
                    "class_name": "demo/App", "member_name": "main",
                    "descriptor": "([Ljava/lang/String;)V",
                },
                "expected": {
                    "required_resources": ["application.properties"],
                },
            }
            destination = root / "materialized"
            with patch(
                "binary_real_project_guard.resolve_asm_jar",
                return_value=root / "asm.jar",
            ):
                materialize_case(
                    manifest, application, base, destination,
                    jdk_home=root / "jdk",
                )
                first = (destination / "business-classes.jar").read_bytes()
                materialize_case(
                    manifest, application, base, destination,
                    jdk_home=root / "jdk",
                )
                second = (destination / "business-classes.jar").read_bytes()
        self.assertEqual(first, second)

    def test_source_build_materializer_uses_pinned_argv_cwd_and_digest(self):
        revision = "1" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = root / "template.jar"
            with zipfile.ZipFile(template, "w") as archive:
                archive.writestr("z.txt", b"z")
                archive.writestr("a.txt", b"a")
            canonical = root / "canonical.jar"
            _canonicalize_zip(template, canonical)
            expected = hashlib.sha256(canonical.read_bytes()).hexdigest()
            asset = {
                "kind": "source_build",
                "filename": "built.jar",
                "repository_url": "https://example.invalid/project.git",
                "git_revision": revision,
                "working_directory": "complete",
                "build_command": ["mvnw", "-q", "package"],
                "artifact_path": "target/application.jar",
                "canonicalize_zip": True,
                "sha256": expected,
            }
            observed = []

            def fake_execute(command, **kwargs):
                observed.append((tuple(command), dict(kwargs)))
                stage = kwargs["stage"]
                if stage.endswith(".clone"):
                    checkout = Path(command[-1])
                    (checkout / "complete").mkdir(parents=True)
                elif stage.endswith(".revision"):
                    return BinaryToolResult(revision + "\n", "", 0)
                elif stage.endswith(".build"):
                    produced = Path(kwargs["cwd"]) / "target" / "application.jar"
                    produced.parent.mkdir(parents=True)
                    with zipfile.ZipFile(produced, "w") as archive:
                        archive.writestr("a.txt", b"a")
                        archive.writestr("z.txt", b"z")
                return BinaryToolResult("", "", 0)

            with patch(
                "binary_real_project_guard.execute_binary_tool",
                side_effect=fake_execute,
            ):
                result = resolve_asset(asset, root / "cache", allow_download=True)
            result_bytes = result.read_bytes()

        self.assertEqual(hashlib.sha256(result_bytes).hexdigest(), expected)
        self.assertEqual(observed[0][0][:4], ("git", "clone", "--quiet", "--no-checkout"))
        self.assertEqual(observed[2][0][-2:], ("rev-parse", "HEAD"))
        build_call = observed[3]
        self.assertEqual(build_call[0], ("mvnw", "-q", "package"))
        self.assertEqual(Path(build_call[1]["cwd"]).name, "complete")

    def test_missing_asset_fails_closed_without_unrequested_download(self):
        manifest = load_guard_manifest(DEFAULT_MANIFEST)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(BinaryRealProjectGuardError) as raised:
                resolve_asset(
                    manifest["assets"]["application"], tmp,
                    allow_download=False,
                )
        self.assertEqual(raised.exception.reason_code, "REAL_PROJECT_ASSET_MISSING")

    def test_cli_missing_asset_returns_typed_json_without_traceback(self):
        home = jdk_home()
        if not home:
            self.skipTest("full JDK required")
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                [
                    sys.executable, str(ROOT / "scripts/binary_real_project_guard.py"),
                    "--cache-root", str(Path(tmp) / "cache"),
                    "--output-root", str(Path(tmp) / "output"),
                    "--jdk-home", str(home),
                ],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn("Traceback", completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(
            payload["issues"][0]["reason_code"], "REAL_PROJECT_ASSET_MISSING"
        )

    def test_cli_serializes_pipeline_contract_error_without_assuming_detail(self):
        from binary_real_project_guard import main

        error = BinaryPipelineError("BINARY_TEST_FAILURE", "typed pipeline detail")
        with patch("binary_real_project_guard.load_guard_manifest", return_value={"assets": {
            "application": {}, "base_dependency": {},
        }}), patch("binary_real_project_guard.resolve_asset", return_value=Path("asset.jar")), patch(
            "binary_real_project_guard.run_guard", side_effect=error
        ), patch("builtins.print") as emitted:
            exit_code = main([
                "--cache-root", "/tmp/cache",
                "--output-root", "/tmp/output",
                "--jdk-home", "/tmp/jdk",
            ])
        self.assertEqual(exit_code, 1)
        payload = json.loads(emitted.call_args.args[0])
        self.assertEqual(payload["issues"], [{
            "reason_code": "BINARY_TEST_FAILURE",
            "detail": "typed pipeline detail",
        }])

    def test_pinned_mybatis_final_artifact_exercises_xml_proxy_dispatch(self):
        if os.environ.get("JUA_RUN_REAL_PROJECT_GUARD") != "1":
            self.skipTest("the release gate runs the pinned real-project probe once")
        home = jdk_home()
        application = Path("/private/tmp/mybatis-sample-xml-4.0.1.jar")
        base = Path.home() / ".m2/repository/org/mybatis/mybatis/3.5.10/mybatis-3.5.10.jar"
        if not home or not application.is_file() or not base.is_file():
            self.skipTest(
                "pinned real-project assets are materialized by the release real-project gate"
            )
        manifest = load_guard_manifest(DEFAULT_MANIFEST)
        with tempfile.TemporaryDirectory() as tmp:
            result = run_guard(
                manifest, application, base, Path(tmp) / "guard", jdk_home=home
            )
        self.assertEqual(result["status"], "passed", result["issues"])
        self.assertGreaterEqual(result["artifact_count"], 30)
        self.assertIn(
            "mybatis_mapper_proxy_dispatch", result["semantic_edge_kinds"]
        )


if __name__ == "__main__":
    unittest.main()
