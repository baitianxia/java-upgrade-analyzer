import csv
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import confidence_weighted_tracer as tracer
import gate
import s1_dep_diff
import s4_jar_compare
import s5_call_chain_engine_integrated as step5


class RetainedArtifactPipelineTest(unittest.TestCase):
    @staticmethod
    def _jar_bytes(entries):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            for name, content in entries:
                archive.writestr(name, content)
        return payload.getvalue()

    def _prepare_step1(self, root, dependency_blobs):
        report = root / "report"
        dependencies = report / "evidence" / "dependencies"
        dependencies.mkdir(parents=True)
        artifact = root / "current.jar"
        current_entries = []
        with zipfile.ZipFile(artifact, "w") as outer:
            outer.writestr("BOOT-INF/classes/app/App.class", b"class")
            outer.writestr(
                "BOOT-INF/classes/application.yml",
                b"spring:\n  application:\n    name: demo\n",
            )
            for index, (coord, blob) in enumerate(dependency_blobs, 1):
                artifact_id = coord.split(":", 1)[1]
                lib_entry = f"BOOT-INF/lib/{artifact_id}-{index}.jar"
                outer.writestr(lib_entry, blob)
                current_entries.append({
                    "coord": coord,
                    "version": "1.0",
                    "scope": "runtime",
                    "lib_entry": lib_entry,
                    "resolution_status": "resolved",
                    "packaged_match_source": "embedded-pom",
                })
        artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
        manifest_path, items = s1_dep_diff.materialize_changed_dependency_jars(
            [],
            {"current": {
                "artifact_path": str(artifact),
                "artifact_sha256": artifact_sha,
            }},
            dependencies,
            current_entries=current_entries,
        )
        with (dependencies / "deps_current_resolved.csv").open(
            "w", encoding="utf-8", newline="",
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "coord", "version", "scope", "lib_entry",
                    "resolution_status", "packaged_match_source",
                ],
            )
            writer.writeheader()
            writer.writerows(current_entries)
        return report, artifact, artifact_sha, manifest_path, items

    def test_step1_retention_pass_opens_current_fat_jar_once_for_all_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dependency = self._jar_bytes([
                ("com/acme/Library.class", b"class"),
            ])
            artifact = root / "current.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/classes/app/App.class", b"class")
                outer.writestr("BOOT-INF/lib/a.jar", dependency)
                outer.writestr("BOOT-INF/lib/b.jar", dependency)
            opens = 0
            real_zip_file = zipfile.ZipFile

            def counting_zip_file(file, *args, **kwargs):
                nonlocal opens
                if Path(str(file)) == artifact:
                    opens += 1
                return real_zip_file(file, *args, **kwargs)

            with patch.object(s1_dep_diff.zipfile, "ZipFile", counting_zip_file):
                manifest_path, items = (
                    s1_dep_diff.materialize_changed_dependency_jars(
                        [],
                        {"current": {
                            "artifact_path": str(artifact),
                            "artifact_sha256": hashlib.sha256(
                                artifact.read_bytes()
                            ).hexdigest(),
                        }},
                        root / "dependencies",
                        current_entries=[
                            {
                                "coord": f"com.acme:{name}",
                                "version": "1.0",
                                "scope": "runtime",
                                "lib_entry": f"BOOT-INF/lib/{name}.jar",
                                "resolution_status": "resolved",
                            }
                            for name in ("a", "b")
                        ],
                    )
                )

            self.assertEqual(opens, 1)
            self.assertEqual(len(items), 2)
            self.assertEqual(
                manifest_path.read_text(encoding="utf-8").count(
                    '"step5_runtime"'
                ),
                2,
            )

    def test_step5_catalog_survives_after_outer_fat_jar_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dependency = self._jar_bytes([
                ("com/acme/Library.class", b"class"),
            ])
            report, artifact, artifact_sha, _manifest, _items = (
                self._prepare_step1(
                    root, [("com.acme:library", dependency)]
                )
            )
            artifact.unlink()

            catalog = step5.build_runtime_dependency_catalog(report)

            self.assertEqual(catalog["status"], "complete")
            self.assertEqual(catalog["final_artifact_sha256"], artifact_sha)
            self.assertNotIn("final_artifact_path", catalog)
            self.assertEqual(
                catalog["by_coord"]["com.acme:library"]["evidence_origin"],
                "step1_retained_dependency_jar",
            )
            self.assertEqual(
                catalog["artifact_safety"]["nested_archives_inspected"], 0
            )
            self.assertIn("__business__", catalog["by_coord"])

            graph = SimpleNamespace(
                report_dir=str(report),
                runtime_dependency_catalog=catalog,
            )
            provenance = tracer._verified_final_artifact_provenance(graph)
            self.assertTrue(provenance["complete"], provenance["failures"])

    def test_same_gav_same_bytes_is_analyzed_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            dependency = self._jar_bytes([
                ("com/acme/Library.class", b"class"),
            ])
            report, _artifact, _sha, _manifest, _items = self._prepare_step1(
                Path(tmp),
                [
                    ("com.acme:library", dependency),
                    ("com.acme:library", dependency),
                ],
            )

            catalog = step5.build_runtime_dependency_catalog(report)

            item = catalog["by_coord"]["com.acme:library"]
            self.assertEqual(catalog["status"], "complete")
            self.assertEqual(len(item["artifact_entries"]), 2)
            self.assertEqual(
                [
                    entry["coord"] for entry in catalog["entries"]
                    if entry["coord"] == "com.acme:library"
                ],
                ["com.acme:library"],
            )

    def test_step1_rejects_same_gav_with_different_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(
                ValueError,
                "Step1 同一 GAV 对应多个不同字节",
            ):
                self._prepare_step1(
                    Path(tmp),
                    [
                        ("com.acme:library", self._jar_bytes([
                            ("com/acme/Library.class", b"one"),
                        ])),
                        ("com.acme:library", self._jar_bytes([
                            ("com/acme/Library.class", b"two"),
                        ])),
                    ],
                )

    def test_step1_rejects_unsafe_retained_business_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "current.jar"
            with zipfile.ZipFile(artifact, "w") as outer:
                outer.writestr("BOOT-INF/classes/app/App.class", b"class")
            dependencies = root / "dependencies"

            with patch.object(
                s1_dep_diff,
                "require_safe_archive",
                side_effect=ValueError(
                    "artifact_safety_violation:"
                    "ARCHIVE_ENTRY_COUNT_EXCEEDED"
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "ARCHIVE_ENTRY_COUNT_EXCEEDED",
                ):
                    s1_dep_diff.materialize_changed_dependency_jars(
                        [],
                        {"current": {
                            "artifact_path": str(artifact),
                            "artifact_sha256": hashlib.sha256(
                                artifact.read_bytes()
                            ).hexdigest(),
                        }},
                        dependencies,
                        current_entries=[],
                    )

            self.assertFalse(
                (dependencies / "dependency_jars.json").exists()
            )
            self.assertFalse(
                (
                    dependencies
                    / "s1_dependency_jars/current/business-classes.jar"
                ).exists()
            )

    def test_step1_gate_rejects_retained_archive_safety_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            retained = Path(tmp) / "retained.jar"
            retained.write_bytes(self._jar_bytes([
                ("app/App.class", b"class"),
            ]))

            with patch.object(
                gate,
                "require_safe_archive",
                side_effect=ValueError(
                    "artifact_safety_violation:"
                    "ARCHIVE_ENTRY_COUNT_EXCEEDED"
                ),
            ):
                with self.assertRaises(SystemExit) as raised:
                    gate.require_safe_step1_retained_archive(
                        retained,
                        "current 业务内容",
                    )

            self.assertEqual(raised.exception.code, 1)

    def test_step5_stops_before_graph_when_retained_catalog_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / ".upgrade-report"
            output = report / "evidence" / "call_chain"
            source = root / "src" / "main" / "java"
            source.mkdir(parents=True)
            api_file = (
                report
                / "evidence"
                / "api_changes"
                / "all_changed_apis.csv"
            )
            api_file.parent.mkdir(parents=True)
            api_file.write_text(
                "coord,api_name\ncom.acme:library,com.acme.Library.call\n",
                encoding="utf-8",
            )
            args = SimpleNamespace(
                report_dir=str(report),
                output_dir=str(output),
                all_changed_apis=str(api_file),
                source_dirs=[str(source)],
                dependency_source_mappings=[],
                allow_degraded=False,
                jdk_scan_dir="",
                max_methods=None,
                max_depth=5,
            )
            invalid_catalog = {
                "by_coord": {},
                "entries": [],
                "status": "insufficient",
                "reason_codes": ["step1_retained_artifact_invalid"],
                "extraction_failures": [{
                    "coord": "com.acme:library",
                    "lib_entry": "BOOT-INF/lib/library.jar",
                    "reason": (
                        "step1_retained_dependency_jar_invalid:"
                        "artifact_safety_violation:"
                        "ARCHIVE_ENTRY_COUNT_EXCEEDED"
                    ),
                }],
            }
            discovery = {
                "dependency_source_mappings": [],
                "matched_coords": [],
                "provided_dependency_source_dirs": [],
                "source_dirs_detected_without_coord": [],
                "unresolved_dependency_source_dirs": [],
                "discovery_log": [],
            }

            with (
                patch.object(
                    step5,
                    "auto_discover_bridge_sources",
                    return_value=discovery,
                ),
                patch.object(
                    step5,
                    "load_changed_apis",
                    return_value=[{
                        "coord": "com.acme:library",
                        "api_name": "com.acme.Library.call",
                    }],
                ),
                patch.object(
                    step5,
                    "build_runtime_dependency_catalog",
                    return_value=invalid_catalog,
                ),
                patch.object(
                    step5,
                    "build_enhanced_source_graph",
                    side_effect=AssertionError(
                        "invalid core evidence must stop before graph build"
                    ),
                ),
            ):
                exit_code = step5.step5_integrated_main(args)

            self.assertEqual(exit_code, 2)
            diagnostic = output / "artifact_preflight_failure.json"
            self.assertTrue(diagnostic.is_file())
            payload = json.loads(
                diagnostic.read_text(encoding="utf-8")
            )
            self.assertEqual(payload["status"], "blocked_by_system")
            self.assertEqual(
                payload["reason_code"],
                "STEP1_RETAINED_ARTIFACT_EVIDENCE_INVALID",
            )
            self.assertFalse((output / "summary.json").exists())

    def test_step4_collapses_same_gav_only_when_retained_hashes_match(self):
        base = {
            "coord": "com.acme:library",
            "old_version": "1.0",
            "new_version": "2.0",
            "change_type": "大版本升级",
            "_step4_base_jar_evidence": {"nested_jar_sha256": "a" * 64},
            "_step4_current_jar_evidence": {"nested_jar_sha256": "b" * 64},
        }
        duplicate = {
            **base,
            "base_lib_entry": "BOOT-INF/lib/library-copy.jar",
            "current_lib_entry": "BOOT-INF/lib/library-copy-2.jar",
        }

        collapsed, conflicts = s4_jar_compare.collapse_same_gav_artifact_rows(
            [base, duplicate]
        )
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(conflicts, [])

        different = {
            **duplicate,
            "_step4_current_jar_evidence": {"nested_jar_sha256": "c" * 64},
        }
        _collapsed, conflicts = s4_jar_compare.collapse_same_gav_artifact_rows(
            [base, different]
        )
        self.assertEqual(
            conflicts[0]["reason_code"],
            "SAME_GAV_DIFFERENT_RETAINED_BYTES",
        )


if __name__ == "__main__":
    unittest.main()
