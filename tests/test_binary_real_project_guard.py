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
    _independent_identical_runtime_oracle,
    evaluate_real_project_formal_truth,
    load_guard_manifest,
    materialize_case,
    resolve_asset,
    run_guard,
    verify_manifest_contract,
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
            expected_methods = set(
                manifest["expected"].get("reachable_changed_methods") or ()
            )
            if expected_methods:
                truth = manifest["expected"]["formal_result_truth"]
                provenance = manifest["expected"]["oracle_provenance"]
                truth_methods = {
                    f"{row['owner']}.{row['member']}"
                    for row in truth["expected_results"]
                }
                self.assertEqual(truth_methods, expected_methods)
                self.assertTrue(truth["forbidden_results"])
                self.assertFalse(provenance["system_generated"])
                self.assertGreaterEqual(len(provenance["oracle_producers"]), 2)
                self.assertEqual(
                    len({
                        row["mechanism"]
                        for row in provenance["oracle_producers"]
                    }),
                    len(provenance["oracle_producers"]),
                )
                oracle_implementation = provenance["oracle_implementation"]
                oracle_path = ROOT / oracle_implementation["path"]
                self.assertTrue(oracle_path.is_file())
                self.assertEqual(
                    hashlib.sha256(oracle_path.read_bytes()).hexdigest(),
                    oracle_implementation["sha256"],
                )
                for row in truth["expected_results"]:
                    for field in (
                        "descriptor", "member_kind", "dependency_lineages",
                        "base_dependency_coords", "current_dependency_coords",
                        "reachability_status", "static_linkage_status",
                        "impact_conclusion", "runtime_verification_status",
                        "exact_path_exists", "possible_path_exists",
                        "minimum_path_count",
                    ):
                        self.assertIn(field, row)

    def test_manifest_rejects_loose_method_only_expectation(self):
        manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        manifest["expected"].pop("formal_result_truth")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(BinaryRealProjectGuardError) as raised:
                load_guard_manifest(path)

        self.assertEqual(
            raised.exception.reason_code, "REAL_PROJECT_FORMAL_TRUTH_MISSING"
        )

    def test_subset_truth_requires_independent_oracle_provenance(self):
        manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        manifest["expected"].pop("oracle_provenance")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(BinaryRealProjectGuardError) as raised:
                load_guard_manifest(path)

        self.assertEqual(
            raised.exception.reason_code,
            "REAL_PROJECT_SUBSET_TRUTH_PROVENANCE_INVALID",
        )

    def test_linkage_oracle_rejects_inconsistent_expected_linkage_state(self):
        manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        manifest["expected"]["formal_result_truth"]["expected_results"][0][
            "static_linkage_status"
        ] = "incompatible_if_executed"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(BinaryRealProjectGuardError) as raised:
                load_guard_manifest(path)

        self.assertEqual(
            raised.exception.reason_code,
            "REAL_PROJECT_ORACLE_EXPECTED_LINKAGE_STATE_INVALID",
        )

    def test_manifest_verification_rejects_changed_oracle_digest(self):
        manifest = load_guard_manifest(DEFAULT_MANIFEST)
        manifest["expected"]["oracle_provenance"]["oracle_implementation"][
            "sha256"
        ] = "0" * 64

        result = verify_manifest_contract(
            manifest, manifest_path=DEFAULT_MANIFEST
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["issues"], [{
                "reason_code": "REAL_PROJECT_ORACLE_IMPLEMENTATION_INVALID",
                "fields": ["sha256_matches"],
            }],
        )

    def test_exact_truth_requires_independent_non_system_provenance(self):
        path = (
            DEFAULT_MANIFEST.parent / "mybatis_sample_xml_noop.json"
        )
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["expected"].pop("oracle_provenance")
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken.json"
            broken.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(BinaryRealProjectGuardError) as raised:
                load_guard_manifest(broken)

        self.assertEqual(
            raised.exception.reason_code,
            "REAL_PROJECT_EXACT_TRUTH_PROVENANCE_INVALID",
        )

    def test_independent_noop_oracle_detects_one_changed_runtime_byte(self):
        manifest = load_guard_manifest(
            DEFAULT_MANIFEST.parent / "mybatis_sample_xml_noop.json"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = root / "base.jar"
            current = root / "current.jar"
            with zipfile.ZipFile(base, "w") as archive:
                archive.writestr("demo/A.class", b"same")
            shutil.copyfile(base, current)
            descriptor = {
                "logical_location": "lib/demo.jar",
                "loader_realm": "application-loader",
                "path_kind": "classpath",
                "slot": 0,
                "coord": "demo:artifact:1",
                "lineage": "demo:artifact",
                "runtime_code_source_origin_identity": "same-origin",
                "outer_artifact_path": str(base),
                "container_entry": "BOOT-INF/lib/demo.jar",
            }
            config = {
                "base": {"artifacts": [{**descriptor, "path": str(base)}]},
                "current": {
                    "artifacts": [{**descriptor, "path": str(current)}]
                },
            }
            matching = _independent_identical_runtime_oracle(config, manifest)
            with zipfile.ZipFile(current, "w") as archive:
                archive.writestr("demo/A.class", b"changed")
            changed = _independent_identical_runtime_oracle(config, manifest)

        self.assertEqual(matching["status"], "passed")
        self.assertEqual(changed["status"], "failed")
        self.assertIn(
            "content_sha256", changed["issues"][0]["fields"]
        )

    def test_real_project_truth_rejects_wrong_overload_as_false_result(self):
        expected = {
            "formal_result_truth": {
                "schema": "java-upgrade-analyzer.binary-result-truth.v1",
                "result_set_policy": "exact",
                "exact_reachability_statuses": ["reachable"],
                "expected_results": [{
                    "owner": "demo/Service", "member": "call",
                    "descriptor": "()V", "member_kind": "method",
                    "reachability_status": "reachable",
                }],
                "forbidden_results": [],
            },
        }
        evaluation = evaluate_real_project_formal_truth({"by_api": [{
            "display_owner": "demo/Service", "display_member": "call",
            "display_descriptor": "(I)V", "display_member_kind": "method",
            "reachability_status": "reachable", "paths": [],
        }]}, expected)

        self.assertEqual(evaluation["status"], "failed")
        self.assertEqual(evaluation["metrics"]["false_negative_count"], 1)
        self.assertEqual(evaluation["metrics"]["false_positive_count"], 1)

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

    def test_published_asset_uses_verified_curl_when_python_ca_path_fails(self):
        payload = b"pinned-real-project-asset"
        asset = {
            "kind": "published",
            "filename": "pinned.jar",
            "url": "https://repo1.maven.org/maven2/example/pinned.jar",
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        observed = []

        def secure_curl(command, **kwargs):
            observed.append((tuple(command), dict(kwargs)))
            output = Path(command[command.index("--output") + 1])
            output.write_bytes(payload)
            return BinaryToolResult("", "", 0)

        with tempfile.TemporaryDirectory() as tmp, patch(
            "binary_real_project_guard.urllib.request.urlopen",
            side_effect=OSError("certificate verify failed"),
        ), patch(
            "binary_real_project_guard.shutil.which", return_value="/usr/bin/curl",
        ), patch(
            "binary_real_project_guard.execute_binary_tool",
            side_effect=secure_curl,
        ):
            resolved = resolve_asset(asset, tmp, allow_download=True)
            actual = resolved.read_bytes()

        self.assertEqual(actual, payload)
        self.assertEqual(len(observed), 1)
        command, options = observed[0]
        self.assertEqual(command[0], "/usr/bin/curl")
        self.assertIn("--fail", command)
        self.assertIn("--proto", command)
        self.assertIn("=https", command)
        self.assertNotIn("--insecure", command)
        self.assertEqual(
            options["stage"], "binary_real_project.download_curl_fallback"
        )

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
