import csv
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import s5_call_chain_engine_integrated as step5  # noqa: E402
import confidence_weighted_tracer as tracer  # noqa: E402
from step5_evidence_model import ModuleScope, classify_module_scope  # noqa: E402
from tests.retained_artifact_test_support import (  # noqa: E402
    retain_current_artifact_contract,
)


def nested_maven_jar(group_id, artifact_id, version="1.0"):
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr(
            f"META-INF/maven/{group_id}/{artifact_id}/pom.properties",
            f"groupId={group_id}\nartifactId={artifact_id}\nversion={version}\n",
        )
        archive.writestr("com/acme/library/Bridge.class", b"fixture")
    return payload.getvalue()


class ArtifactIdentityOwnershipInvariantTest(unittest.TestCase):
    def build_catalog(self, included_modules):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        report = root / "report"
        application = root / "application.jar"
        with zipfile.ZipFile(application, "w") as archive:
            archive.writestr(
                "META-INF/maven/com.acme/application/pom.properties",
                "groupId=com.acme\nartifactId=application\nversion=1.0\n",
            )
            archive.writestr("BOOT-INF/classes/com/acme/App.class", b"fixture")
            archive.writestr(
                "BOOT-INF/lib/library-1.0.jar",
                nested_maven_jar("com.acme", "library"),
            )
        dependencies = report / "evidence/dependencies"
        dependencies.mkdir(parents=True)
        with (dependencies / "deps_current_resolved.csv").open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "coord", "version", "scope", "lib_entry", "resolution_status"
                ],
            )
            writer.writeheader()
            writer.writerow({
                "coord": "com.acme:library",
                "version": "1.0",
                "scope": "runtime",
                "lib_entry": "BOOT-INF/lib/library-1.0.jar",
                "resolution_status": "resolved",
            })
        artifact_sha = hashlib.sha256(application.read_bytes()).hexdigest()
        (dependencies / "build_provenance.json").write_text(json.dumps({
            "sides": [{
                "side": "current",
                "artifact_path": str(application),
                "artifact_sha256": artifact_sha,
            }]
        }), encoding="utf-8")
        retain_current_artifact_contract(report, application)
        state = report / ".runtime/state/main_state.json"
        state.parent.mkdir(parents=True)
        state.write_text(json.dumps({
            "step5": {"input": {"project_scope": {
                "included_module_coords": included_modules,
            }}}
        }), encoding="utf-8")
        return step5.build_runtime_dependency_catalog(report), artifact_sha

    def test_same_group_dependency_is_not_internal_without_reactor_membership(self):
        catalog, _artifact_sha = self.build_catalog(["com.acme:application"])
        item = catalog["by_coord"]["com.acme:library"]

        self.assertIs(item["application_owned"], False)
        self.assertNotIn("ownership_evidence", item)
        self.assertEqual(classify_module_scope(item), ModuleScope.EXTERNAL_DEPENDENCY)

    def test_reactor_nested_module_has_final_artifact_ownership_evidence(self):
        catalog, artifact_sha = self.build_catalog(
            ["com.acme:application", "com.acme:library"]
        )
        item = catalog["by_coord"]["com.acme:library"]

        self.assertIs(item["application_owned"], True)
        self.assertEqual(item["ownership_evidence"], {
            "authority": "reactor_coordinate_and_final_artifact_entry",
            "reactor_coord": "com.acme:library",
            "artifact_entry": "BOOT-INF/lib/library-1.0.jar",
            "final_artifact_sha256": artifact_sha,
        })
        self.assertEqual(classify_module_scope(item), ModuleScope.INTERNAL_MODULE)

    def test_reactor_nested_module_classes_are_not_business_entry_alignment(self):
        catalog, _artifact_sha = self.build_catalog(
            ["com.acme:application", "com.acme:library"]
        )

        classes = step5.runtime_business_class_index(catalog)

        self.assertEqual(classes, {"com.acme.App"})

    def test_missing_orchestrator_state_recovers_scope_from_reactor_and_artifact(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "pom.xml").write_text(
            """<project><modelVersion>4.0.0</modelVersion>
            <groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version>
            <packaging>pom</packaging><modules><module>application</module><module>library</module></modules>
            </project>""",
            encoding="utf-8",
        )
        for module in ("application", "library"):
            module_dir = root / module
            (module_dir / "src/main/java/com/acme").mkdir(parents=True)
            (module_dir / "pom.xml").write_text(
                f"""<project><modelVersion>4.0.0</modelVersion>
                <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
                <artifactId>{module}</artifactId>
                {('<dependencies><dependency><groupId>com.acme</groupId><artifactId>library</artifactId>'
                  '<version>1.0</version></dependency></dependencies>') if module == 'application' else ''}
                </project>""",
                encoding="utf-8",
            )

        report = root / "report"
        application = root / "application.jar"
        with zipfile.ZipFile(application, "w") as archive:
            archive.writestr(
                "META-INF/maven/com.acme/application/pom.properties",
                "groupId=com.acme\nartifactId=application\nversion=1.0\n",
            )
            archive.writestr("BOOT-INF/classes/com/acme/App.class", b"fixture")
            archive.writestr(
                "BOOT-INF/lib/library-1.0.jar",
                nested_maven_jar("com.acme", "library"),
            )
        dependencies = report / "evidence/dependencies"
        dependencies.mkdir(parents=True)
        with (dependencies / "deps_current_resolved.csv").open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "coord", "version", "scope", "lib_entry", "resolution_status"
                ],
            )
            writer.writeheader()
            writer.writerow({
                "coord": "com.acme:library",
                "version": "1.0",
                "scope": "runtime",
                "lib_entry": "BOOT-INF/lib/library-1.0.jar",
                "resolution_status": "resolved",
            })
        artifact_sha = hashlib.sha256(application.read_bytes()).hexdigest()
        (dependencies / "build_provenance.json").write_text(json.dumps({
            "sides": [{
                "side": "current",
                "artifact_path": str(application),
                "artifact_sha256": artifact_sha,
            }]
        }), encoding="utf-8")
        retain_current_artifact_contract(report, application)

        catalog = step5.build_runtime_dependency_catalog(
            report,
            business_source_dirs=[root],
        )

        item = catalog["by_coord"]["com.acme:library"]
        self.assertIs(item["application_owned"], True)
        self.assertEqual(
            item["ownership_evidence"]["reactor_coord"],
            "com.acme:library",
        )

    def test_scope_recovery_does_not_promote_same_group_non_reactor_jar(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "pom.xml").write_text(
            """<project><modelVersion>4.0.0</modelVersion>
            <groupId>com.acme</groupId><artifactId>application</artifactId><version>1.0</version>
            </project>""",
            encoding="utf-8",
        )
        artifact = root / "application.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr(
                "META-INF/maven/com.acme/application/pom.properties",
                "groupId=com.acme\nartifactId=application\nversion=1.0\n",
            )
            archive.writestr(
                "BOOT-INF/lib/library-1.0.jar",
                nested_maven_jar("com.acme", "library"),
            )

        recovered = step5._recover_reactor_module_coords(
            [root], {"com.acme:application", "com.acme:library"}
        )

        self.assertEqual(recovered, {"com.acme:application"})
        self.assertNotIn("com.acme:library", recovered)

    def test_unproved_application_owned_flag_cannot_create_internal_scope(self):
        self.assertEqual(
            classify_module_scope({
                "coord": "com.acme:library",
                "application_owned": True,
            }),
            ModuleScope.UNKNOWN,
        )

    def test_mismatched_reactor_coordinate_cannot_create_internal_scope(self):
        self.assertEqual(
            classify_module_scope({
                "coord": "com.acme:library",
                "application_owned": True,
                "ownership_evidence": {
                    "authority": "reactor_coordinate_and_final_artifact_entry",
                    "reactor_coord": "com.acme:other",
                    "artifact_entry": "BOOT-INF/lib/library-1.0.jar",
                    "final_artifact_sha256": "a" * 64,
                },
            }),
            ModuleScope.UNKNOWN,
        )

    @unittest.skipUnless(shutil.which("javac"), "JDK compiler required")
    def test_runtime_scan_preserves_verified_internal_module_ownership(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        sources = root / "src/com/acme/library"
        sources.mkdir(parents=True)
        (sources / "Target.java").write_text(
            "package com.acme.library; public class Target { "
            "public void removed() {} }",
            encoding="utf-8",
        )
        (sources / "Bridge.java").write_text(
            "package com.acme.library; public class Bridge { "
            "public void call() { new Target().removed(); } }",
            encoding="utf-8",
        )
        classes = root / "classes"
        completed = subprocess.run(
            ["javac", "-d", str(classes), *map(str, sources.glob("*.java"))],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        nested = root / "library.jar"
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr(
                "META-INF/maven/com.acme/library/pom.properties",
                "groupId=com.acme\nartifactId=library\nversion=1.0\n",
            )
            for class_file in classes.rglob("*.class"):
                archive.write(class_file, class_file.relative_to(classes).as_posix())

        catalog = {
            "status": "complete",
            "target_jdk": "17",
            "by_coord": {
                "com.acme:library": {
                    "coord": "com.acme:library",
                    "jar_path": str(nested),
                    "artifact_entry": "BOOT-INF/lib/library.jar",
                    "application_owned": True,
                    "ownership_evidence": {
                        "authority": "reactor_coordinate_and_final_artifact_entry",
                        "reactor_coord": "com.acme:library",
                        "artifact_entry": "BOOT-INF/lib/library.jar",
                        "final_artifact_sha256": "a" * 64,
                    },
                }
            },
        }
        scan = tracer._scan_packaged_runtime_dependencies_for_api({
            "coord": "com.acme:library",
            "api_name": "com.acme.library.Target.removed",
            "api_simple": "removed",
            "api_signature": "()",
            "symbol_kind": "method",
        }, SimpleNamespace(runtime_dependency_catalog=catalog))

        self.assertEqual(scan["status"], "hit")
        bridge_hit = next(
            item for item in scan["hits"]
            if item["class_fqcn"] == "com.acme.library.Bridge"
        )
        self.assertEqual(
            classify_module_scope(bridge_hit),
            ModuleScope.INTERNAL_MODULE,
        )
        self.assertEqual(
            bridge_hit["ownership_evidence"],
            catalog["by_coord"]["com.acme:library"]["ownership_evidence"],
        )


if __name__ == "__main__":
    unittest.main()
