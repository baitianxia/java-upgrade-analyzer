import io
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
import zipfile
import zlib

from tests.blackbox.test_public_runtime_dispatch import (
    compile_jar,
    jdk_home,
    public_pipeline,
    side,
)


ROOT = Path(__file__).resolve().parents[2]
TRUTH = json.loads((
    ROOT / "tests" / "fixtures" / "blackbox_runtime"
    / "runtime_topology_v1.json"
).read_text(encoding="utf-8"))


def execute(command: list[str]) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=180,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout={completed.stdout[-3000:]}\nstderr={completed.stderr[-3000:]}"
        )
    return completed


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def append_resources(jar: Path, resources: dict[str, str]) -> None:
    with zipfile.ZipFile(jar, "a", zipfile.ZIP_DEFLATED) as archive:
        for name, value in resources.items():
            archive.writestr(name, value)


def standard_config(base: dict, current: dict, *, release_snapshot: bool = False) -> dict:
    comparison = {
        "controlled_profile_fields": ["loader_topology"],
        "declared_upgrade_payload_scope": ["artifact-bytes"],
    }
    if release_snapshot:
        comparison.update({
            "comparison_intent": "release_snapshot",
            "profile_correspondence_policy_version": "v1",
            "changed_or_unknown_profile_fields": [
                "ordered_runtime_path_entry_descriptors",
            ],
        })
    return {
        "schema": "java-upgrade-analyzer.binary-pipeline-input.v1",
        "source_usage": {
            "decision": "skip_source", "decision_source": "explicit_config",
        },
        "base": base,
        "current": current,
        "runtime_comparison": comparison,
    }


def reconciliation_rows(generation: Path, side_name: str) -> list[dict]:
    database = generation / f"{side_name}_binary_facts.sqlite"
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        columns = {
            row[1] for row in connection.execute(
                "PRAGMA table_info(reconciliation_records)"
            )
        }
        chunks = [dict(row) for row in connection.execute(
            "SELECT * FROM reconciliation_records ORDER BY record_kind,chunk_identity"
        )]
    if not columns or not chunks:
        raise AssertionError("public reconciliation evidence is empty")
    kind_names = {
        1: "provider_binding", 2: "class_definition", 3: "member_resolution",
        4: "dispatch_resolution", 5: "type_resolution",
        6: "class_initialization_resolution", 7: "linkage_resolution",
        8: "resource_selection",
    }
    rows = []
    for chunk in chunks:
        envelopes = json.loads(zlib.decompress(chunk["payload_zlib"]).decode("utf-8"))
        if len(envelopes) != chunk["record_count"]:
            raise AssertionError("reconciliation chunk count mismatch")
        for envelope in envelopes:
            rows.append({
                "record_kind": kind_names[chunk["record_kind"]],
                "record_identity": envelope["record_identity"],
                "status": envelope["status"],
                "subject_identity": envelope["subject_identity"],
                "payload_json": json.dumps(envelope["payload"]),
            })
    return rows


def artifact_origins(generation: Path, side_name: str) -> dict[str, str]:
    database = generation / f"{side_name}_binary_facts.sqlite"
    with sqlite3.connect(database) as connection:
        return {
            identity: origin
            for identity, origin in connection.execute(
                "SELECT artifact_instance_identity,runtime_code_source_origin_identity "
                "FROM artifact_instances"
            )
        }


def class_entries(generation: Path, side_name: str) -> dict[str, str]:
    database = generation / f"{side_name}_binary_facts.sqlite"
    with sqlite3.connect(database) as connection:
        return {
            identity: entry
            for identity, entry in connection.execute(
                "SELECT class_variant_identity,physical_entry_label FROM classes"
            )
        }


def payload(row: dict) -> dict:
    for key in ("record_json", "payload_json", "evidence_json"):
        value = row.get(key)
        if value:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return {**row, **parsed}
    return row


class PublicRuntimeTopologyBlackboxTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.java = shutil.which("java") or ""
        cls.javac = shutil.which("javac") or ""
        cls.javap = shutil.which("javap") or ""
        if not all((cls.java, cls.javac, cls.javap)):
            raise AssertionError("OpenJDK java, javac, and javap are required")
        cls.home = jdk_home(cls.java)

    def test_multi_release_selection_matches_actual_jvm(self):
        truth = TRUTH["cases"]["multi_release"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "mr-base", {
                "lib/Target.java": "package lib; public class Target { public int value(){return 1;} }",
            }, self.javac)
            version = compile_jar(root, "mr-version", {
                "lib/Target.java": "package lib; public class Target { public int value(){return 2;} }",
            }, self.javac)
            current = root / "mr-current.jar"
            with zipfile.ZipFile(base) as base_archive, zipfile.ZipFile(version) as version_archive:
                with zipfile.ZipFile(current, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr(
                        "META-INF/MANIFEST.MF",
                        "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
                    )
                    archive.writestr("lib/Target.class", base_archive.read("lib/Target.class"))
                    archive.writestr(
                        "META-INF/versions/9/lib/Target.class",
                        version_archive.read("lib/Target.class"),
                    )
            business = compile_jar(root, "mr-business", {
                "biz/Entry.java": "package biz; public class Entry { public int run(){return new lib.Target().value();} public static void main(String[] a){System.out.print(new Entry().run());} }",
            }, self.javac, classpath=(base,))
            for dependency, field in (
                (base, "expected_base_stdout"), (current, "expected_current_stdout"),
            ):
                observed = execute([
                    self.java, "-cp", os.pathsep.join((str(business), str(dependency))),
                    "biz.Entry",
                ])
                self.assertEqual(observed.stdout, truth[field])
            with zipfile.ZipFile(current) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [
                        "META-INF/MANIFEST.MF", "lib/Target.class",
                        "META-INF/versions/9/lib/Target.class",
                    ],
                )
                self.assertEqual(
                    archive.read("META-INF/MANIFEST.MF"),
                    b"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
                )
            version_contract = execute([
                self.javap, "--multi-release", "9", "-classpath", str(current),
                "-c", "lib.Target",
            ]).stdout
            self.assertRegex(version_contract, r"iconst_2")

            entrypoint = ("biz/Entry", "run", "()I")
            result, formal, _overlay = public_pipeline(
                root / "mr-report",
                standard_config(
                    side(self.home, business, base, "1", entrypoint),
                    side(self.home, business, current, "2", entrypoint),
                ),
            )
            self.assertEqual(result["validation_status"], "passed")
            target = next(
                row for row in formal["by_api"]
                if (
                    row["display_owner"], row["display_member"],
                    row["display_descriptor"], row["display_member_kind"],
                ) == tuple(truth["target"])
            )
            for field, value in truth["expected_state"].items():
                self.assertEqual(target[field], value, (field, target))
            current_rows = [payload(row) for row in reconciliation_rows(
                Path(result["generation_directory"]), "current"
            )]
            selected = [
                row for row in current_rows
                if row.get("record_kind") == "provider_binding"
                and row.get("class_name") == "lib/Target"
            ]
            self.assertEqual(len(selected), 1, current_rows[:10])
            self.assertEqual(
                class_entries(
                    Path(result["generation_directory"]), "current"
                )[selected[0]["selected_class_variant_identity"]],
                truth["selected_current_entry"],
            )

    def test_target_jvm_and_platform_module_definition_success_is_public(self):
        truth = TRUTH["cases"]["target_jvm_definition"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = compile_jar(root, "definition-base", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public String value(){return \"1:platform\";} }"
                ),
            }, self.javac)
            current = compile_jar(root, "definition-current", {
                "lib/Target.java": (
                    "package lib; public class Target { "
                    "public String value(){return \"2:platform\";} }"
                ),
            }, self.javac)
            business = compile_jar(root, "definition-business", {
                "biz/Entry.java": (
                    "package biz; public class Entry { "
                    "public String run(){return new lib.Target().value();} "
                    "public static void main(String[] a){"
                    "System.out.print(new Entry().run());} }"
                ),
            }, self.javac, classpath=(base,))
            entrypoint = ("biz/Entry", "run", "()Ljava/lang/String;")
            for dependency, field in (
                (base, "expected_base_stdout"),
                (current, "expected_current_stdout"),
            ):
                observed = execute([
                    self.java, "-Xverify:all", "-cp",
                    os.pathsep.join((str(business), str(dependency))),
                    "biz.Entry",
                ])
                self.assertEqual(observed.stdout, truth[field])

            result, _formal, _overlay = public_pipeline(
                root / "definition-report",
                standard_config(
                    side(self.home, business, base, "1", entrypoint),
                    side(self.home, business, current, "2", entrypoint),
                ),
            )
            self.assertEqual(result["validation_status"], "passed")
            definition_path = Path(result["definition_verification_path"])
            self.assertTrue(definition_path.is_file())
            public = json.loads(definition_path.read_text(encoding="utf-8"))
            release = {}
            for line in (self.home / "release").read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    release[key] = value.strip().strip('"')
            expected_major = int(release["JAVA_VERSION"].split(".", 1)[0])
            modules_digest = sha256_file(self.home / "lib" / "modules")

            self.assertEqual(
                public["schema"],
                "java-upgrade-analyzer.binary-definition-verification.v1",
            )
            self.assertEqual(
                public["authority"],
                "target_jvm_execution_and_bound_platform_image",
            )
            for side_name in ("base", "current"):
                side_result = public[side_name]
                self.assertEqual(side_result["coverage_status"], "complete")
                self.assertEqual(side_result["failure_count"], 0)
                self.assertEqual(side_result["failure_samples"], [])
                self.assertEqual(
                    side_result["definition_status_counts"],
                    {truth["expected_definition_status"]: side_result[
                        "class_definition_count"
                    ]},
                )
                self.assertGreater(side_result["target_jvm_verified_class_count"], 0)
                self.assertEqual(
                    side_result["target_jvm_status_counts"],
                    {
                        truth["expected_target_verification_status"]:
                        side_result["target_jvm_verified_class_count"]
                    },
                )
                self.assertEqual(
                    len(side_result["class_definition_verifier_identities"]), 1
                )
                self.assertTrue(
                    set(truth["required_platform_classes"])
                    <= set(side_result["platform_class_names"])
                )
                image = side_result["runtime_platform_image"]
                self.assertEqual(image["java_major"], expected_major)
                self.assertEqual(image["module_image_sha256"], modules_digest)
                self.assertGreater(image["indexed_class_count"], 1000)
                self.assertGreaterEqual(
                    image["loaded_class_count"],
                    len(truth["required_platform_classes"]),
                )

    def test_classpath_and_resource_order_match_actual_classloader(self):
        truth = TRUTH["cases"]["classpath_and_resources"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provider_a = compile_jar(root, "provider-a", {
                "dup/Provider.java": "package dup; public class Provider { public static int value(){return 1;} }",
            }, self.javac)
            provider_b = compile_jar(root, "provider-b", {
                "dup/Provider.java": "package dup; public class Provider { public static int value(){return 2;} }",
            }, self.javac)
            append_resources(provider_a, {
                truth["first_resource_name"]: "A",
                truth["resource_name"]: "A",
            })
            append_resources(provider_b, {
                truth["first_resource_name"]: "B",
                truth["resource_name"]: "B",
            })
            business = compile_jar(root, "ordered-business", {
                "biz/Entry.java": """
                    package biz; public class Entry {
                      static String text(java.net.URL url) throws Exception {
                        try (java.io.InputStream in=url.openStream()) {
                          return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                        }
                      }
                      public String run() throws Exception {
                        ClassLoader loader=Entry.class.getClassLoader();
                        String first=text(loader.getResource("config/value.txt"));
                        java.util.Enumeration<java.net.URL> all=loader.getResources("META-INF/services/example.Service");
                        StringBuilder order=new StringBuilder(); while(all.hasMoreElements()) order.append(text(all.nextElement()));
                        return dup.Provider.value()+":"+first+":"+order;
                      }
                      public static void main(String[] args) throws Exception { System.out.print(new Entry().run()); }
                    }
                """,
            }, self.javac, classpath=(provider_a,))
            for dependencies, field in (
                ((provider_a, provider_b), "expected_base_stdout"),
                ((provider_b, provider_a), "expected_current_stdout"),
            ):
                observed = execute([
                    self.java, "-cp", os.pathsep.join(map(str, (business, *dependencies))),
                    "biz.Entry",
                ])
                self.assertEqual(observed.stdout, truth[field])
            for jar, expected_value in ((provider_a, b"A"), (provider_b, b"B")):
                with zipfile.ZipFile(jar) as archive:
                    self.assertEqual(archive.read(truth["resource_name"]), expected_value)
                    self.assertEqual(
                        archive.read(truth["first_resource_name"]), expected_value
                    )
                    self.assertIn("dup/Provider.class", archive.namelist())

            entrypoint = ("biz/Entry", "run", "()Ljava/lang/String;")

            def ordered_side(first: tuple[Path, str], second: tuple[Path, str]) -> dict:
                profile = side(self.home, business, first[0], "unused", entrypoint)
                profile["artifacts"] = [profile["artifacts"][0]]
                for slot, (path, lineage) in enumerate((first, second), 1):
                    profile["artifacts"].append({
                        "path": str(path),
                        "logical_location": f"lib/slot-{slot}.jar",
                        "loader_realm": "application-loader",
                        "path_kind": "classpath",
                        "slot": slot,
                        "coord": f"{lineage}:1",
                        "lineage": lineage,
                        "runtime_code_source_origin_identity": lineage,
                    })
                return profile

            base_side = ordered_side(
                (provider_a, "blackbox:provider-a"),
                (provider_b, "blackbox:provider-b"),
            )
            current_side = ordered_side(
                (provider_b, "blackbox:provider-b"),
                (provider_a, "blackbox:provider-a"),
            )
            result, _formal, _overlay = public_pipeline(
                root / "ordered-report",
                standard_config(base_side, current_side, release_snapshot=True),
            )
            self.assertEqual(result["validation_status"], "passed")
            generations = Path(result["generation_directory"])

            def selected_evidence(side_name: str) -> tuple[str, list[str]]:
                rows = [payload(row) for row in reconciliation_rows(generations, side_name)]
                origins = artifact_origins(generations, side_name)
                provider = next(
                    row for row in rows
                    if row.get("record_kind") == "provider_binding"
                    and row.get("class_name") == truth["class_name"]
                )
                resource = next(
                    row for row in rows
                    if row.get("record_kind") == "resource_selection"
                    and row.get("resource_name") == truth["resource_name"]
                )
                return (
                    origins[provider["selected_artifact_instance_identity"]],
                    [
                        item["runtime_code_source_origin_identity"]
                        for item in resource["selected_resources"]
                    ],
                )

            base_selected, base_resources = selected_evidence("base")
            current_selected, current_resources = selected_evidence("current")
            self.assertEqual(base_selected, truth["base_selected_lineage"])
            self.assertEqual(current_selected, truth["current_selected_lineage"])
            self.assertEqual(base_resources, truth["base_resource_order"])
            self.assertEqual(current_resources, truth["current_resource_order"])

    def test_parent_first_realm_shadows_child_provider_like_urlclassloader(self):
        truth = TRUTH["cases"]["parent_first"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent_base = compile_jar(root, "parent-base", {
                "dup/Provider.java": "package dup; public class Provider { public static int value(){return 1;} }",
            }, self.javac)
            parent_current = compile_jar(root, "parent-current", {
                "dup/Provider.java": "package dup; public class Provider { public static int value(){return 3;} }",
            }, self.javac)
            child_provider = compile_jar(root, "child-provider", {
                "dup/Provider.java": "package dup; public class Provider { public static int value(){return 2;} }",
            }, self.javac)
            business = compile_jar(root, "realm-business", {
                "biz/Entry.java": "package biz; public class Entry { public int run(){return dup.Provider.value();} public static void main(String[] a){System.out.print(new Entry().run());} }",
            }, self.javac, classpath=(child_provider,))
            oracle = compile_jar(root, "realm-oracle", {
                "oracle/Main.java": """
                    package oracle;
                    public class Main {
                      public static void main(String[] args) throws Exception {
                        java.net.URL parentUrl = java.nio.file.Path.of(args[0]).toUri().toURL();
                        java.net.URL businessUrl = java.nio.file.Path.of(args[1]).toUri().toURL();
                        java.net.URL childUrl = java.nio.file.Path.of(args[2]).toUri().toURL();
                        try (java.net.URLClassLoader parent = new java.net.URLClassLoader(
                               new java.net.URL[]{parentUrl}, ClassLoader.getPlatformClassLoader());
                             java.net.URLClassLoader child = new java.net.URLClassLoader(
                               new java.net.URL[]{businessUrl, childUrl}, parent)) {
                          Class<?> entry = Class.forName("biz.Entry", true, child);
                          System.out.print(entry.getMethod("run").invoke(entry.getConstructor().newInstance()));
                        }
                      }
                    }
                """,
            }, self.javac)
            for parent, field in (
                (parent_base, "expected_base_stdout"),
                (parent_current, "expected_current_stdout"),
            ):
                observed = execute([
                    self.java, "-cp", str(oracle), "oracle.Main",
                    str(parent), str(business), str(child_provider),
                ])
                self.assertEqual(observed.stdout, truth[field])
            shadow = execute([
                self.java, "-cp", os.pathsep.join((str(business), str(child_provider))),
                "biz.Entry",
            ])
            self.assertEqual(shadow.stdout, truth["shadow_stdout"])

            entrypoint = ("biz/Entry", "run", "()I")

            def realm_side(parent: Path, version: str) -> dict:
                profile = {
                    "container_and_launcher_kind": "custom-url-classloader",
                    "loader_topology": {
                        "coverage_status": "complete",
                        "entrypoint_realms": ["child-loader"],
                        "realms": [
                            {"identity": "platform-loader", "kind": "platform", "delegation": "parent_first", "module_mode": "named-platform"},
                            {"identity": "parent-loader", "kind": "application", "parent": "platform-loader", "delegation": "parent_first", "module_mode": "unnamed"},
                            {"identity": "child-loader", "kind": "application", "parent": "parent-loader", "delegation": "parent_first", "module_mode": "unnamed"},
                        ],
                    },
                    "runtime_security_and_package_sealing_policy_identity": "standard-unsealed-unsigned-v1",
                    "active_profile_identities": ["default"],
                    "external_config_snapshot_identities": [],
                    "agent_transformer_plugin_profile_identities": [],
                    "business_entrypoint_profile": {
                        "coverage_status": "complete",
                        "methods": [{
                            "initiating_loader_realm_identity": "child-loader",
                            "class_name": entrypoint[0],
                            "member_name": entrypoint[1],
                            "descriptor": entrypoint[2],
                        }],
                    },
                    "runtime_class_closure_coverage_status": "complete",
                    "resource_selection_coverage_status": "complete",
                }
                return {
                    "jdk_home": str(self.home),
                    "artifacts": [
                        {
                            "path": str(business), "logical_location": "child/business.jar",
                            "loader_realm": "child-loader", "path_kind": "business_classes",
                            "slot": 0, "coord": "blackbox:realm-business:1",
                            "lineage": "blackbox:realm-business",
                            "runtime_code_source_origin_identity": "blackbox:realm-business",
                        },
                        {
                            "path": str(child_provider), "logical_location": "child/provider.jar",
                            "loader_realm": "child-loader", "path_kind": "classpath",
                            "slot": 1, "coord": "blackbox:child-provider:1",
                            "lineage": "blackbox:child-provider",
                            "runtime_code_source_origin_identity": "blackbox:child-provider",
                        },
                        {
                            "path": str(parent), "logical_location": "parent/provider.jar",
                            "loader_realm": "parent-loader", "path_kind": "classpath",
                            "slot": 0, "coord": f"blackbox:parent-provider:{version}",
                            "lineage": "blackbox:parent-provider",
                            "runtime_code_source_origin_identity": "blackbox:parent-provider",
                        },
                    ],
                    "runtime_profile": profile,
                }

            result, formal, _overlay = public_pipeline(
                root / "parent-first-report",
                standard_config(
                    realm_side(parent_base, "1"),
                    realm_side(parent_current, "2"),
                ),
            )
            self.assertEqual(result["validation_status"], "passed")
            target = next(
                row for row in formal["by_api"]
                if row["display_owner"] == truth["class_name"]
                and row["display_member"] == "value"
            )
            self.assertEqual(target["reachability_status"], "reachable")
            self.assertEqual(
                target["current_dependency_coords"],
                ["blackbox:parent-provider:2"],
            )
            generation = Path(result["generation_directory"])
            rows = [payload(row) for row in reconciliation_rows(generation, "current")]
            provider = next(
                row for row in rows
                if row.get("record_kind") == "provider_binding"
                and row.get("initiating_loader_realm_identity") == "child-loader"
                and row.get("class_name") == truth["class_name"]
            )
            origins = artifact_origins(generation, "current")
            self.assertEqual(
                origins[provider["selected_artifact_instance_identity"]],
                truth["selected_lineage"],
            )
            self.assertEqual(
                provider["selected_defining_loader_realm_identity"],
                "parent-loader",
            )


if __name__ == "__main__":
    unittest.main()
