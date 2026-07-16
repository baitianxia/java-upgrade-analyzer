import csv
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s1_dep_diff as step1  # noqa: E402
import s2_context_from_deps as step2  # noqa: E402
import s4_jar_compare as step4  # noqa: E402
import s5_call_chain_engine_integrated as step5  # noqa: E402
import real_project_regression as realreg  # noqa: E402


class FinalArtifactOnlyPolicyTest(unittest.TestCase):
    @staticmethod
    def _nested_jar_bytes(entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, value in entries:
                archive.writestr(name, value)
        return buffer.getvalue()

    def test_step4_japicmp_never_reads_or_downloads_analyzed_dependency_jars(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool_jar = Path(tmp) / "japicmp.jar"
            tool_jar.write_bytes(b"tool")

            with patch.object(
                step4, "find_jar_in_m2", side_effect=AssertionError("不得读取本地仓库"), create=True
            ), patch.object(
                step4, "fetch_jar_from_repo", side_effect=AssertionError("不得下载被分析 JAR"), create=True
            ):
                _output, rows, details, error = step4.run_japicmp(
                    "org.example:demo", "1.0", "2.0", tmp, str(tool_jar)
                )

            self.assertEqual(rows, [])
            self.assertEqual(details["reason_code"], "FINAL_ARTIFACT_JAR_EVIDENCE_MISSING")
            self.assertIn("最终制品", error)

    def test_step4_removed_dependency_never_reads_or_downloads_old_jar(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(
                step4, "find_jar_in_m2", side_effect=AssertionError("不得读取本地仓库"), create=True
            ), patch.object(
                step4, "fetch_jar_from_repo", side_effect=AssertionError("不得下载被分析 JAR"), create=True
            ):
                _output, rows, details, error = step4.export_removed_jar_apis(
                    "org.example:legacy", "1.0", tmp
                )

            self.assertEqual(rows, [])
            self.assertEqual(details["reason_code"], "BASE_FINAL_ARTIFACT_JAR_EVIDENCE_MISSING")
            self.assertIn("最终制品", error)

    def test_step4_resolver_explains_missing_final_artifact_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "evidence"
            dependencies = report / "dependencies"
            dependencies.mkdir(parents=True)
            artifact = Path(tmp) / "app.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/lib/other-1.0.jar", b"not-the-target")
            (dependencies / "build_provenance.json").write_text(
                json.dumps({"sides": [{"side": "current", "artifact_path": str(artifact)}]}),
                encoding="utf-8",
            )
            resolver = step4.Step1ArtifactJarResolver(report, Path(tmp) / "api_changes")
            row = {"current_lib_entry": "BOOT-INF/lib/demo-1.0.jar"}

            self.assertIsNone(resolver.resolve_for_row(row, "current"))
            failure = resolver.failure_for_row(row, "current")
            self.assertEqual(failure["reason_code"], "FINAL_ARTIFACT_LIB_ENTRY_NOT_FOUND")
            self.assertEqual(failure["lib_entry"], "BOOT-INF/lib/demo-1.0.jar")

    def test_step5_runtime_catalog_does_not_fallback_to_local_maven(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp)
            deps_dir = report / "evidence" / "dependencies"
            deps_dir.mkdir(parents=True)
            with (deps_dir / "deps_current_resolved.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["coord", "version", "scope", "lib_entry"])
                writer.writeheader()
                writer.writerow(
                    {
                        "coord": "org.example:demo",
                        "version": "2.0",
                        "scope": "runtime",
                        "lib_entry": "BOOT-INF/lib/demo-2.0.jar",
                    }
                )

            with patch.object(
                step5, "_find_maven_jar", side_effect=AssertionError("不得读取本地仓库"), create=True
            ):
                catalog = step5.build_runtime_dependency_catalog(str(report))

            self.assertNotIn("org.example:demo", catalog["by_coord"])
            self.assertIn("runtime_dependency_jars_missing", catalog["reason_codes"])
            self.assertNotIn("local_maven_fallback_used", catalog["reason_codes"])

    def test_step5_source_metadata_does_not_resolve_dependency_source_from_local_maven(self):
        source_roots = [{"owner_type": "dependency", "owner_coord": "org.example:demo"}]
        with patch.object(
            step5, "_find_maven_jar", side_effect=AssertionError("不得读取本地仓库"), create=True
        ):
            metadata = step5.build_jar_metadata_for_source_roots(
                source_roots,
                "/path/that/does/not/exist",
                runtime_dependency_catalog={"by_coord": {}},
            )
        self.assertEqual(metadata["jar_paths"], {})

    def test_step1_filename_only_coordinate_enrichment_ignores_local_maven(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = self._nested_jar_bytes([("org/example/Demo.class", b"class")])
            local_repo = root / "repository"
            local_jar = local_repo / "wrong" / "owner" / "demo" / "1.0" / "demo-1.0.jar"
            local_jar.parent.mkdir(parents=True)
            local_jar.write_bytes(nested)
            artifact = root / "app.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/lib/demo-1.0.jar", nested)
            loader_calls = []

            def runtime_loader():
                loader_calls.append(True)
                return {
                    "org.example:demo": {
                        "group_id": "org.example",
                        "artifact_id": "demo",
                        "version": "1.0",
                        "scope": "runtime",
                    }
                }

            with patch.dict(os.environ, {"MAVEN_REPO_LOCAL": str(local_repo)}):
                dependencies, metadata = step1.collect_packaged_deps_from_artifact_path(
                    str(artifact), runtime_deps_loader=runtime_loader
                )

            self.assertEqual(loader_calls, [True])
            self.assertIn("org.example:demo", dependencies)
            self.assertNotEqual(metadata["dep_entries"][0]["match_source"], "local-m2-sha256")

    def test_step2_legacy_raw_pom_helper_never_accesses_maven_repository(self):
        with patch.object(step2, "maven_repo_dir", side_effect=AssertionError("不得读取本地仓库"), create=True), patch.object(
            step2, "run_cmd", side_effect=AssertionError("不得下载 POM")
        ):
            self.assertEqual(step2.get_pom_deps_from_m2("org.example", "demo", "1.0"), [])

    def test_real_project_regression_artifacts_never_point_at_local_maven_repository(self):
        offenders = {
            name: str(case.final_artifact)
            for name, case in realreg.CASES.items()
            if case.final_artifact is not None and ".m2" in case.final_artifact.parts
        }
        self.assertEqual(offenders, {})


if __name__ == "__main__":
    unittest.main()
