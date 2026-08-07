import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
FIXTURE = ROOT / "tests" / "fixtures" / "topologies"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import final_artifact_edge_oracle as oracle  # noqa: E402
import topology_coverage  # noqa: E402


JDK_TOOLS = shutil.which("javac") and shutil.which("javap") and shutil.which("java")


def _compile(output: Path, sources: list[Path], classpath: list[Path] | None = None) -> None:
    output.mkdir(parents=True, exist_ok=True)
    command = ["javac", "-d", str(output)]
    if classpath:
        command.extend(["-classpath", os.pathsep.join(str(item) for item in classpath)])
    command.extend(str(item) for item in sources)
    subprocess.run(command, check=True, capture_output=True, text=True)


def _jar_classes(path: Path, classes: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for class_file in sorted(classes.rglob("*.class")):
            archive.write(class_file, class_file.relative_to(classes).as_posix())


@unittest.skipUnless(JDK_TOOLS, "JDK tools required")
class TopologyCoverageTest(unittest.TestCase):
    def test_sha_bound_runtime_verified_mybatis_semantics_define_proxy_topology(self):
        target = "org.apache.ibatis.binding.MapperMethod.execute"
        layout = {
            "authority": "final_artifact_edge_oracle",
            "complete": True,
            "target_apis": [{
                "owner": "org.apache.ibatis.binding.MapperMethod",
                "member": "execute",
                "descriptor": (
                    "(Lorg/apache/ibatis/session/SqlSession;[Ljava/lang/Object;)"
                    "Ljava/lang/Object;"
                ),
            }],
            "entry_layout": [],
            "semantic_references": [{
                "target_class": target,
                "authority": "final-artifact-mybatis-proxy-runtime",
                "artifact_sha256": "a" * 64,
                "artifact_entry": (
                    "BOOT-INF/lib/mybatis-3.5.19.jar!/"
                    "org/apache/ibatis/binding/MapperMethod.class"
                ),
                "runtime_output_sha256": "b" * 64,
                "proxy_dispatch_edge_count": 3,
                "physical_evidence_count": 1,
            }],
        }

        observed = topology_coverage.classify_topologies([], layout)

        self.assertIn("mybatis_mapper_proxy", observed)

    def test_mybatis_semantic_for_unselected_api_does_not_define_proxy_topology(self):
        layout = {
            "authority": "final_artifact_edge_oracle",
            "complete": True,
            "target_apis": [{
                "owner": "org.apache.ibatis.binding.MapperMethod",
                "member": "execute",
                "descriptor": "()V",
            }],
            "entry_layout": [],
            "semantic_references": [{
                "target_class": "org.apache.ibatis.session.SqlSession.selectOne",
                "authority": "final-artifact-mybatis-proxy-runtime",
                "artifact_sha256": "a" * 64,
                "artifact_entry": "BOOT-INF/lib/mybatis.jar!/org/apache/ibatis/session/SqlSession.class",
                "runtime_output_sha256": "b" * 64,
                "proxy_dispatch_edge_count": 3,
            }],
        }

        observed = topology_coverage.classify_topologies([], layout)

        self.assertNotIn("mybatis_mapper_proxy", observed)

    def test_classfile_semantic_reference_counts_as_uncertain_reflection_topology(self):
        target = "com.vendor.OptionalSecurityType"
        layout = {
            "authority": "final_artifact_edge_oracle",
            "complete": True,
            "target_apis": [{"owner": target, "member": "", "descriptor": ""}],
            "entry_layout": [],
            "semantic_references": [{
                "target_class": target,
                "authority": "final-artifact-classfile-constants",
                "artifact_sha256": "a" * 64,
                "artifact_entry": "app/SecurityModule.class",
            }],
        }

        observed = topology_coverage.classify_topologies([], layout)

        self.assertIn("reflection", observed)

    def test_removed_class_semantic_reference_still_defines_reflection_topology(self):
        target = "com.vendor.RemovedSecurityType"
        layout = {
            "authority": "final_artifact_edge_oracle",
            "complete": True,
            "target_apis": [],
            "entry_layout": [],
            "semantic_references": [{
                "api_identity": (
                    "com.vendor:security|com.vendor.RemovedSecurityType||class|REMOVED"
                ),
                "target_class": target,
                "authority": "final-artifact-classfile-constants",
                "artifact_sha256": "a" * 64,
                "artifact_entry": "app/SecurityModule.class",
            }],
        }

        observed = topology_coverage.classify_topologies([], layout)

        self.assertIn("reflection", observed)

    def test_removed_class_semantic_reference_rejects_mismatched_api_identity(self):
        layout = {
            "authority": "final_artifact_edge_oracle",
            "complete": True,
            "target_apis": [],
            "entry_layout": [],
            "semantic_references": [{
                "api_identity": "com.vendor:security|com.vendor.OtherType||class|REMOVED",
                "target_class": "com.vendor.RemovedSecurityType",
                "authority": "final-artifact-classfile-constants",
                "artifact_sha256": "a" * 64,
                "artifact_entry": "app/SecurityModule.class",
            }],
        }

        observed = topology_coverage.classify_topologies([], layout)

        self.assertNotIn("reflection", observed)

    def test_transaction_proxy_topology_requires_packaged_runtime_annotation(self):
        target = (
            "org.springframework.transaction.interceptor.TransactionInterceptor",
            "invoke",
            "(Lorg/aopalliance/intercept/MethodInvocation;)Ljava/lang/Object;",
        )
        inventory = {
            "classes": {
                "BOOT-INF/classes/example/BookingService.class": (
                    b"org/springframework/transaction/annotation/Transactional"
                ),
                "BOOT-INF/lib/spring-tx.jar!/org/springframework/transaction/"
                "interceptor/TransactionInterceptor.class": b"tx",
                "BOOT-INF/lib/spring-aop.jar!/org/springframework/aop/framework/"
                "ReflectiveMethodInvocation.class": b"aop",
            }
        }
        annotation = (
            "RuntimeVisibleAnnotations:\n"
            "  org.springframework.transaction.annotation.Transactional\n"
        )

        with mock.patch.object(topology_coverage, "_javap_text", return_value=annotation):
            links = topology_coverage._spring_transaction_proxy_evidence(
                inventory, {target}
            )

        layout = {
            "authority": "final_artifact_edge_oracle",
            "complete": True,
            "target_apis": [{
                "owner": target[0], "member": target[1], "descriptor": target[2],
            }],
            "entry_layout": [],
            "framework_proxy_links": links,
        }
        self.assertIn("framework_proxy", topology_coverage.classify_topologies([], layout))

        with mock.patch.object(topology_coverage, "_javap_text", return_value=""):
            self.assertEqual(
                topology_coverage._spring_transaction_proxy_evidence(inventory, {target}),
                [],
            )

    def test_target_identity_can_be_resolved_from_packaged_declaration(self):
        row = {
            "coord": "org.springframework:spring-tx",
            "api_name": (
                "org.springframework.transaction.interceptor.TransactionInterceptor.invoke"
            ),
            "api_signature": "(org.aopalliance.intercept.MethodInvocation)",
            "symbol_kind": "method",
        }
        entry = (
            "BOOT-INF/lib/spring-tx.jar!/org/springframework/transaction/"
            "interceptor/TransactionInterceptor.class"
        )
        method = {
            "member": "invoke",
            "descriptor": (
                "(Lorg/aopalliance/intercept/MethodInvocation;)Ljava/lang/Object;"
            ),
        }
        with mock.patch.object(
            topology_coverage, "_topology_javap_methods",
            return_value=(
                "org.springframework.transaction.interceptor.TransactionInterceptor",
                [method],
            ),
        ):
            targets, unresolved = topology_coverage._selected_target_identities(
                [row], [], {"classes": {entry: b"class"}}
            )

        self.assertEqual(unresolved, [])
        self.assertEqual(targets[0]["descriptor"], method["descriptor"])

    def test_descriptor_source_signature_uses_source_nested_class_notation(self):
        self.assertEqual(
            topology_coverage.descriptor_source_signature(
                "(Lexample/Outer$Callback;)Ljava/lang/Object;"
            ),
            "(example.Outer.Callback)",
        )

    def test_target_identity_accepts_binary_nested_class_signature(self):
        row = {
            "coord": "example:nested",
            "api_name": "example.Outer$Builder.withCallback",
            "api_signature": "(example.Outer$Callback)",
            "symbol_kind": "method",
        }
        entry = "BOOT-INF/lib/nested.jar!/example/Outer$Builder.class"
        method = {
            "member": "withCallback",
            "descriptor": "(Lexample/Outer$Callback;)Lexample/Outer$Builder;",
        }
        with mock.patch.object(
            topology_coverage,
            "_topology_javap_methods",
            return_value=("example.Outer$Builder", [method]),
        ):
            targets, unresolved = topology_coverage._selected_target_identities(
                [row], [], {"classes": {entry: b"class"}}
            )

        self.assertEqual(unresolved, [])
        self.assertEqual(targets[0]["descriptor"], method["descriptor"])

    def test_target_identity_accepts_source_nested_class_owner(self):
        row = {
            "coord": "example:nested",
            "api_name": "example.Outer.Builder.withCallback",
            "api_signature": "(example.Outer.Callback)",
            "symbol_kind": "method",
        }
        entry = "BOOT-INF/lib/nested.jar!/example/Outer$Builder.class"
        method = {
            "member": "withCallback",
            "descriptor": "(Lexample/Outer$Callback;)Lexample/Outer$Builder;",
        }
        with mock.patch.object(
            topology_coverage,
            "_topology_javap_methods",
            return_value=("example.Outer$Builder", [method]),
        ):
            targets, unresolved = topology_coverage._selected_target_identities(
                [row], [], {"classes": {entry: b"class"}}
            )

        self.assertEqual(unresolved, [])
        self.assertEqual(targets[0]["owner"], "example.Outer$Builder")

    def test_bulk_topology_skips_unreferenced_method_declaration_javap(self):
        row = {
            "coord": "example:api",
            "api_name": "example.Api.unused",
            "api_signature": "()",
            "symbol_kind": "method",
        }
        inventory = {
            "classes": {"BOOT-INF/lib/api.jar!/example/Api.class": b"class"}
        }

        with mock.patch.object(
            topology_coverage, "_topology_javap_methods"
        ) as javap:
            targets, unresolved = topology_coverage._selected_target_identities(
                [row], [], inventory, resolve_unreferenced=False
            )

        javap.assert_not_called()
        self.assertEqual(targets, [])
        self.assertEqual(unresolved, [])

    def test_unreferenced_resolution_is_limited_to_explicit_owner_mappings(self):
        mapped = {
            "coord": "example:mapped",
            "api_name": "example.Mapped.present",
            "api_signature": "()",
            "symbol_kind": "method",
        }
        authoritative_absence = {
            "coord": "example:absent",
            "api_name": "example.Absent.removed",
            "api_signature": "()",
            "symbol_kind": "method",
        }
        entry = "example/Mapped.class"
        inventory = {"classes": {entry: b"class"}}
        method = {"member": "present", "descriptor": "()V"}

        with mock.patch.object(
            topology_coverage,
            "_topology_javap_methods",
            return_value=("example.Mapped", [method]),
        ):
            targets, unresolved = topology_coverage._selected_target_identities(
                [mapped, authoritative_absence],
                [],
                inventory,
                resolve_unreferenced=True,
                unreferenced_owner_allowlist={"example.Mapped"},
            )

        self.assertEqual(unresolved, [])
        self.assertEqual([target["owner"] for target in targets], ["example.Mapped"])

    def test_bulk_topology_does_not_treat_changed_class_as_a_call_target(self):
        row = {
            "coord": "example:api",
            "api_name": "example.RemovedType",
            "api_signature": "",
            "symbol_kind": "class",
        }

        targets, unresolved = topology_coverage._selected_target_identities(
            [row], [], {"classes": {}}, resolve_unreferenced=False
        )

        self.assertEqual(targets, [])
        self.assertEqual(unresolved, [])

    def test_artifact_topology_reuses_precomputed_oracle_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            changed_rows = self._selected_api_rows(expectations)
            scan = oracle.scan_final_artifact(
                artifact,
                selected_targets=topology_coverage._oracle_targets_from_rows(changed_rows),
            )

            with mock.patch.object(
                topology_coverage,
                "scan_final_artifact",
                side_effect=AssertionError("oracle scan was repeated"),
            ):
                evidence = topology_coverage.extract_artifact_topology_evidence(
                    artifact,
                    changed_rows,
                    {
                        "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                        "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                    },
                    oracle_scan=scan,
                )

        self.assertTrue(evidence["complete"], evidence["errors"])

    def test_nested_target_module_with_business_upstream_is_same_coordinate_multimodule(self):
        target = ("fixture.Target", "changed", "()V")
        layout = {
            "authority": "final_artifact_edge_oracle",
            "complete": True,
            "target_apis": [{
                "owner": target[0], "member": target[1], "descriptor": target[2],
                "coordinate": "fixture:library",
            }],
            "entry_layout": [
                {
                    "prefix": "BOOT-INF/lib/library.jar!/",
                    "role": "target",
                    "coordinate": "fixture:library",
                },
                {"prefix": "BOOT-INF/classes/", "role": "business", "coordinate": "__business__"},
            ],
        }
        edges = [
            {
                "artifact_entry": "BOOT-INF/lib/library.jar!/fixture/Bridge.class",
                "caller_owner": "fixture.Bridge", "caller_member": "call", "caller_descriptor": "()V",
                "callee_owner": target[0], "callee_member": target[1], "callee_descriptor": target[2],
                "opcode_family": "invokevirtual",
            },
            {
                "artifact_entry": "BOOT-INF/classes/fixture/App.class",
                "caller_owner": "fixture.App", "caller_member": "run", "caller_descriptor": "()V",
                "callee_owner": "fixture.Bridge", "callee_member": "call", "callee_descriptor": "()V",
                "opcode_family": "invokevirtual",
            },
        ]

        observed = topology_coverage.classify_topologies(edges, layout)

        self.assertIn("same_coord_multimodule", observed)

    def test_topology_oracle_is_scoped_to_every_selected_api(self):
        scan_result = {
            "edges": [], "complete": True, "artifact_sha256": "a" * 64, "failures": [],
        }
        inventory = {"classes": {}, "resources": {}, "containers": set()}
        with mock.patch.object(
            topology_coverage, "scan_final_artifact", return_value=scan_result
        ) as scan_oracle, mock.patch.object(
            topology_coverage, "_archive_inventory", return_value=inventory
        ):
            topology_coverage.extract_artifact_topology_evidence(
                Path("artifact.jar"),
                [{
                    "api_name": "fixture.Target.changed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                }],
                {},
            )

        scan_oracle.assert_called_once_with(
            Path("artifact.jar"),
            selected_targets=[{
                "owner": "fixture.Target", "member": "changed", "descriptor": "",
            }],
        )

    def test_boot_inventory_ignores_duplicate_root_class_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "boot.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("sample/App.class", b"root-copy")
                archive.writestr("BOOT-INF/classes/sample/App.class", b"runtime-copy")
                archive.writestr("BOOT-INF/classes/sample/OnlyRuntime.class", b"runtime-only")

            inventory = topology_coverage._archive_inventory(artifact)

        self.assertEqual(
            sorted(inventory["classes"]),
            [
                "BOOT-INF/classes/sample/App.class",
                "BOOT-INF/classes/sample/OnlyRuntime.class",
            ],
        )

    def test_classfile_hierarchy_fast_path_avoids_javap_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "Child.java"
            source.write_text(
                "interface Contract {} class Parent {} class Child extends Parent implements Contract {}\n",
                encoding="utf-8",
            )
            output = root / "classes"
            _compile(output, [source])
            content = (output / "Child.class").read_bytes()

            with mock.patch.object(
                topology_coverage.subprocess, "run",
                side_effect=AssertionError("javap must not run for a valid classfile header"),
            ):
                parents, error = topology_coverage._class_header_parents(content, 1.0)

        self.assertEqual(error, "")
        self.assertEqual(parents, ("Parent", "Contract"))

    def _build_fixture(
        self,
        root: Path,
        *,
        reflection_resource: str = "META-INF/jua/authoritative-reflection-registration.json",
        proxy_resource: str = "META-INF/jua/authoritative-framework-proxy-registration.json",
    ) -> tuple[Path, dict]:
        source_root = FIXTURE / "src"
        business_sources = sorted((source_root / "business").rglob("*.java"))
        bytecode_sources = sorted((source_root / "bytecode").rglob("*.java"))
        target_sources = sorted((source_root / "target").rglob("*.java"))
        samecoord_sources = sorted((source_root / "samecoord").rglob("*.java"))
        crossjar_sources = sorted((source_root / "crossjar").rglob("*.java"))

        contracts = root / "contracts"
        _compile(
            contracts,
            [item for item in business_sources if {"proxy", "spi"} & set(item.parts)],
        )
        target_classes = root / "target-classes"
        _compile(target_classes, target_sources, [contracts])
        shutil.copytree(contracts, target_classes, dirs_exist_ok=True)
        target_jar = root / "target.jar"
        _jar_classes(target_jar, target_classes)

        samecoord_classes = root / "samecoord-classes"
        _compile(samecoord_classes, samecoord_sources, [target_jar])
        samecoord_jar = root / "samecoord.jar"
        _jar_classes(samecoord_jar, samecoord_classes)

        crossjar_classes = root / "crossjar-classes"
        _compile(crossjar_classes, crossjar_sources, [target_jar])
        crossjar_jar = root / "crossjar.jar"
        _jar_classes(crossjar_jar, crossjar_classes)

        business_classes = root / "business-classes"
        _compile(business_classes, business_sources, [target_jar, samecoord_jar, crossjar_jar])
        _compile(business_classes, bytecode_sources, [target_jar, samecoord_jar, crossjar_jar])
        artifact = root / "topologies.jar"
        reflection_registration = json.dumps({
            "authority": "fixture-reflection-registry",
            "authority_version": "1",
            "procedure": "validated packaged reflection registration",
            "target": "topology.target.TargetApi.changed()V",
            "runtime_registration": {"target": "topology.target.TargetApi.changed()V", "validated": True},
        }).encode()
        proxy_registration = json.dumps({
            "authority": "fixture-proxy-registry",
            "authority_version": "1",
            "procedure": "validated target-specific proxy registration",
            "contract": "topology.proxy.ProxyContract",
            "target": "topology.target.TargetApi.changed()V",
            "runtime_registration": {"target": "topology.target.TargetApi.changed()V", "validated": True},
        }).encode()
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr(
                "META-INF/MANIFEST.MF",
                "Manifest-Version: 1.0\r\nMain-Class: topology.business.App\r\n\r\n",
            )
            for class_file in sorted(business_classes.rglob("*.class")):
                relative = class_file.relative_to(business_classes).as_posix()
                archive.write(class_file, relative)
                archive.write(class_file, "BOOT-INF/classes/" + relative)
            for classes in (target_classes, samecoord_classes, crossjar_classes):
                for class_file in sorted(classes.rglob("*.class")):
                    relative = class_file.relative_to(classes).as_posix()
                    if not (business_classes / relative).exists():
                        archive.write(class_file, relative)
            archive.write(target_jar, "BOOT-INF/lib/target.jar")
            archive.write(samecoord_jar, "BOOT-INF/lib/samecoord.jar")
            archive.write(crossjar_jar, "BOOT-INF/lib/crossjar.jar")
            archive.writestr(
                "META-INF/services/topology.spi.TopologyService",
                "topology.target.TopologyProvider\n"
                "topology.business.UnrelatedProvider\n"
                "topology.business.WrongContractProvider\n",
            )
            archive.writestr(reflection_resource, reflection_registration)
            archive.writestr(proxy_resource, proxy_registration)

        manifest = json.loads((FIXTURE / "manifest.json").read_text(encoding="utf-8"))
        return artifact, manifest

    def _source_attestation(
        self, root: Path, artifact: Path, expectations: dict, *,
        runtime_binding: bool = False, object_format: str = "",
    ) -> tuple[Path, Path]:
        repository = root / "source-repository"
        shutil.copytree(FIXTURE / "src", repository / "src")
        init_command = ["git", "init", "-q"]
        if object_format:
            init_command.append(f"--object-format={object_format}")
        subprocess.run(init_command + [str(repository)], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.email", "fixture@example.test"], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.name", "Topology Fixture"], check=True)
        subprocess.run(["git", "-C", str(repository), "add", "src"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-q", "-m", "fixture source"], check=True)
        revision = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        tree = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD^{tree}"], capture_output=True, text=True, check=True).stdout.strip()
        evidence_path = root / "source_edges.json"
        evidence_path.write_text(json.dumps({
            "source_edges": expectations["source_edges"],
            "source_conflicts": [
                {**item, "evidence_authority": "external_fixture_source_compiler"}
                for item in expectations["source_conflicts"]
            ],
        }, sort_keys=True), encoding="utf-8")
        attestation_path = root / "source_attestation.json"
        attestation = {
            "authority": "external-fixture-source-attestor",
            "authority_version": "1",
            "procedure": "compile and enumerate exact source JVM descriptors",
            "git_revision": revision,
            "git_tree": tree,
            "source_path": "src",
            "source_tree_sha256": topology_coverage.compute_source_tree_sha256(repository / "src"),
            "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "evidence_path": str(evidence_path),
            "evidence_sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
        }
        if runtime_binding:
            attestation["artifact_binding"] = "runtime"
            attestation["reference_artifact_sha256"] = "0" * 64
            attestation.pop("artifact_sha256")
        attestation_path.write_text(json.dumps(attestation, sort_keys=True), encoding="utf-8")
        return repository, attestation_path

    def test_runtime_source_attestation_binds_current_artifact_sha(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            source_root, source_attestation = self._source_attestation(
                root, artifact, expectations, runtime_binding=True
            )
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
                source_root=source_root,
                source_attestation=source_attestation,
            )

        layout = evidence["artifact_layout"]
        provenance = layout["source_provenance"]
        self.assertTrue(provenance["valid"], provenance)
        self.assertEqual(provenance["bound_artifact_sha256"], layout["artifact_sha256"])
        self.assertIn(
            "source_bytecode_agree",
            topology_coverage.classify_topologies(evidence["edges"], layout),
        )

    def test_sha256_repository_source_attestation_is_valid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            try:
                source_root, source_attestation = self._source_attestation(
                    root, artifact, expectations, object_format="sha256"
                )
            except subprocess.CalledProcessError as error:
                self.skipTest(f"Git SHA-256 repositories unsupported: {error}")
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": [
                        "BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"
                    ],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
                source_root=source_root,
                source_attestation=source_attestation,
            )

        provenance = evidence["artifact_layout"]["source_provenance"]
        self.assertEqual(len(provenance["git_revision"]), 64)
        self.assertTrue(provenance["valid"], provenance)
        self.assertIn(
            "source_bytecode_agree",
            topology_coverage.classify_topologies(
                evidence["edges"], evidence["artifact_layout"]
            ),
        )

    def test_real_final_artifact_oracle_classifies_every_stable_topology(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            source_root, source_attestation = self._source_attestation(root, artifact, expectations)
            selected_rows = self._selected_api_rows(expectations)
            scan = oracle.scan_final_artifact(
                artifact,
                selected_targets=topology_coverage._oracle_targets_from_rows(selected_rows),
            )
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                selected_rows,
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
                source_root=source_root,
                source_attestation=source_attestation,
            )

        self.assertTrue(scan["complete"], scan["failures"])
        self.assertTrue(evidence["complete"], evidence["errors"])
        for expected in expectations["expected_edges"]:
            self.assertTrue(any(all(row.get(key) == value for key, value in expected.items()) for row in scan["edges"]), expected)
        self.assertEqual(
            topology_coverage.classify_topologies(evidence["edges"], evidence["artifact_layout"]),
            set(expectations["stable_topology_ids"]),
        )

    def _selected_api_rows(self, expectations: dict) -> list[dict]:
        rows = []
        for target in expectations["target_apis"]:
            descriptor = target["descriptor"]
            signature = topology_coverage.descriptor_source_signature(descriptor)
            rows.append({
                "coord": "topology:library",
                "api_name": f"{target['owner']}.{target['member']}",
                "api_signature": signature,
                "symbol_kind": "field" if not descriptor.startswith("(") else "method",
            })
        return rows

    def test_fixture_is_an_executable_jar(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, _layout = self._build_fixture(Path(temp_dir))
            completed = subprocess.run(
                ["java", "-jar", str(artifact)], capture_output=True, text=True, check=False
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_registration_topologies_require_explicit_packaged_authority(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, expectations = self._build_fixture(Path(temp_dir))
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
            )

        layout = evidence["artifact_layout"]
        layout["registrations"] = []
        layout["reflection_target_links"] = []
        observed = topology_coverage.classify_topologies(evidence["edges"], layout)

        self.assertNotIn("reflection", observed)
        self.assertNotIn("spi", observed)
        self.assertNotIn("framework_proxy", observed)

    def test_reflection_requires_authoritative_packaged_registration_tied_to_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            source_root, source_attestation = self._source_attestation(root, artifact, expectations)
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
                source_root=source_root,
                source_attestation=source_attestation,
            )

        layout = evidence["artifact_layout"]
        layout["registrations"] = [
            item for item in layout["registrations"] if item.get("kind") != "reflection"
        ]
        observed = topology_coverage.classify_topologies(evidence["edges"], layout)

        self.assertNotIn("reflection", observed)

    def test_reflection_does_not_match_a_registered_overload_without_parameter_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, expectations = self._build_fixture(Path(temp_dir))
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
            )

        layout = evidence["artifact_layout"]
        layout["target_apis"].append({
            "owner": "topology.target.TargetApi", "member": "changed",
            "descriptor": "(Ljava/lang/String;)V", "coordinate": "topology:library",
        })

        self.assertNotIn(
            "reflection",
            topology_coverage.classify_topologies(evidence["edges"], layout),
        )

    def test_reflection_legacy_resource_and_dataflow_alone_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, expectations = self._build_fixture(
                Path(temp_dir), reflection_resource="META-INF/jua/reflection.json"
            )
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
            )

        self.assertTrue(evidence["artifact_layout"]["reflection_target_links"])
        self.assertFalse(any(
            item.get("kind") == "reflection"
            for item in evidence["artifact_layout"]["registrations"]
        ))
        self.assertNotIn(
            "reflection",
            topology_coverage.classify_topologies(evidence["edges"], evidence["artifact_layout"]),
        )

    def test_proxy_requires_versioned_procedure_and_target_runtime_registration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
            )

        layout = evidence["artifact_layout"]
        for item in layout["registrations"]:
            if item.get("kind") == "framework_proxy":
                item.pop("authority_version", None)
                item.pop("procedure", None)
                item.pop("runtime_registration", None)
        observed = topology_coverage.classify_topologies(evidence["edges"], layout)

        self.assertNotIn("framework_proxy", observed)

    def test_arbitrary_legacy_proxy_resource_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, expectations = self._build_fixture(
                Path(temp_dir), proxy_resource="META-INF/jua/proxy.json"
            )
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
            )

        self.assertFalse(any(
            item.get("kind") == "framework_proxy"
            for item in evidence["artifact_layout"]["registrations"]
        ))
        self.assertNotIn(
            "framework_proxy",
            topology_coverage.classify_topologies(evidence["edges"], evidence["artifact_layout"]),
        )

    def test_expectation_manifest_cannot_self_declare_authority(self):
        expectations = json.loads((FIXTURE / "manifest.json").read_text(encoding="utf-8"))

        observed = topology_coverage.classify_topologies([], expectations)

        self.assertEqual(observed, set())

    def test_unrelated_invokedynamic_bootstrap_does_not_cover_selected_target(self):
        target = {
            "owner": "topology.target.TargetApi", "member": "changed", "descriptor": "()V"
        }
        edges = [
            {
                "artifact_sha256": "a" * 64,
                "artifact_entry": "BOOT-INF/classes/topology/business/App.class",
                "caller_owner": "topology.business.App", "caller_member": "run", "caller_descriptor": "()V",
                "callee_owner": "java.lang.invoke.LambdaMetafactory", "callee_member": "metafactory",
                "callee_descriptor": "()V", "opcode_family": "invokedynamic", "authority": "jdk-javap",
            }
        ]
        layout = {
            "authority": "final_artifact_edge_oracle",
            "complete": True,
            "target_apis": [target],
            "entry_layout": [{"prefix": "BOOT-INF/classes/", "role": "business"}],
            "bootstrap_target_links": [],
        }

        self.assertNotIn("invokedynamic", topology_coverage.classify_topologies(edges, layout))

    def test_extractor_excludes_unrelated_packaged_dynamic_reflection_and_spi_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, expectations = self._build_fixture(Path(temp_dir))
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
            )

        unrelated_dynamic = "topology.business.UnrelatedDynamic"
        unrelated_reflection = "topology.business.UnrelatedReflection"
        unrelated_provider = "topology.business.UnrelatedProvider"
        wrong_contract_provider = "topology.business.WrongContractProvider"
        colocated_reflection = "topology.business.CoLocatedReflection"
        adversarial_reflection = "topology.business.AdversarialReflection"
        self.assertFalse(any(row["caller_owner"] == unrelated_dynamic for row in evidence["edges"]))
        self.assertFalse(any(row["caller_owner"] == unrelated_reflection for row in evidence["edges"]))
        self.assertFalse(any(item.get("caller", [None])[0] in {unrelated_dynamic, unrelated_reflection} for item in evidence["artifact_layout"]["bootstrap_target_links"] + evidence["artifact_layout"]["reflection_target_links"]))
        self.assertFalse(any(item.get("provider") == unrelated_provider for item in evidence["artifact_layout"]["registrations"]))
        self.assertFalse(any(item.get("provider") == wrong_contract_provider for item in evidence["artifact_layout"]["registrations"]))
        self.assertFalse(any(item.get("caller", [None])[0] == colocated_reflection for item in evidence["artifact_layout"]["reflection_target_links"]))
        self.assertFalse(any(item.get("caller", [None])[0] == adversarial_reflection for item in evidence["artifact_layout"]["reflection_target_links"]))
        provider_records = [item for item in evidence["artifact_layout"]["registrations"] if item.get("provider") == "topology.target.TopologyProvider"]
        self.assertTrue(provider_records)
        self.assertTrue(all(item["provider_entry"].startswith("BOOT-INF/lib/target.jar!/") for item in provider_records))
        self.assertTrue(all(
            topology_coverage._entry_scope(item["child_entry"]) == topology_coverage._entry_scope(item["parent_entry"])
            for item in evidence["artifact_layout"]["hierarchy_evidence"]
        ))

    def test_missing_exact_coordinate_mapping_rejects_ambiguous_root_and_nested_targets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, expectations = self._build_fixture(Path(temp_dir))
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {},
            )

        self.assertFalse(evidence["complete"])
        self.assertTrue(any("ambiguous target artifact entries" in item for item in evidence["errors"]))

    def test_external_jdk_target_does_not_need_its_class_packaged_in_the_artifact(self):
        target_edge = {
            "artifact_sha256": "a" * 64,
            "artifact_entry": "BOOT-INF/classes/sample/App.class",
            "caller_owner": "sample.App",
            "caller_member": "run",
            "caller_descriptor": "()V",
            "callee_owner": "java.util.concurrent.CountDownLatch",
            "callee_member": "countDown",
            "callee_descriptor": "()V",
            "opcode_family": "invokevirtual",
            "instruction_offset": 4,
        }
        inventory = {
            "classes": {"BOOT-INF/classes/sample/App.class": b"fixture"},
            "resources": {},
            "containers": set(),
        }
        hierarchy = {
            "relations": [],
            "errors": [],
            "metrics": {
                "class_entries": 1,
                "completed_class_entries": 1,
                "timed_out_class_entries": 0,
                "worker_count": 1,
                "elapsed_sec": 0.0,
            },
        }
        with mock.patch.object(
            topology_coverage, "_archive_inventory", return_value=inventory
        ), mock.patch.object(
            topology_coverage, "_scan_class_hierarchy", return_value=hierarchy
        ):
            evidence = topology_coverage.extract_artifact_topology_evidence(
                Path("application.jar"),
                [{
                    "coord": "jdk:java.base",
                    "api_name": "java.util.concurrent.CountDownLatch.countDown",
                    "api_signature": "()",
                    "symbol_kind": "method",
                }],
                {},
                oracle_scan={
                    "edges": [target_edge],
                    "complete": True,
                    "artifact_sha256": "a" * 64,
                    "failures": [],
                },
            )

        self.assertTrue(evidence["complete"], evidence["errors"])
        self.assertIn(
            "business_direct",
            topology_coverage.classify_topologies(
                evidence["edges"], evidence["artifact_layout"]
            ),
        )

    def test_mapped_runtime_target_must_exist_in_the_final_artifact(self):
        target_edge = {
            "artifact_sha256": "a" * 64,
            "artifact_entry": "BOOT-INF/classes/sample/App.class",
            "caller_owner": "sample.App",
            "caller_member": "run",
            "caller_descriptor": "()V",
            "callee_owner": "com.vendor.Target",
            "callee_member": "removed",
            "callee_descriptor": "()V",
            "opcode_family": "invokevirtual",
            "instruction_offset": 4,
        }
        inventory = {
            "classes": {"BOOT-INF/classes/sample/App.class": b"fixture"},
            "resources": {},
            "containers": set(),
        }
        hierarchy = {
            "relations": [],
            "errors": [],
            "metrics": {
                "class_entries": 1,
                "completed_class_entries": 1,
                "timed_out_class_entries": 0,
                "worker_count": 1,
                "elapsed_sec": 0.0,
            },
        }
        with mock.patch.object(
            topology_coverage, "_archive_inventory", return_value=inventory
        ), mock.patch.object(
            topology_coverage, "_scan_class_hierarchy", return_value=hierarchy
        ):
            evidence = topology_coverage.extract_artifact_topology_evidence(
                Path("application.jar"),
                [{
                    "coord": "com.vendor:target",
                    "api_name": "com.vendor.Target.removed",
                    "api_signature": "()",
                    "symbol_kind": "method",
                }],
                {"com.vendor:target": ["BOOT-INF/lib/target.jar"]},
                oracle_scan={
                    "edges": [target_edge],
                    "complete": True,
                    "artifact_sha256": "a" * 64,
                    "failures": [],
                },
            )

        self.assertFalse(evidence["complete"])
        self.assertIn(
            "target class absent from mapped final artifact: com.vendor.Target",
            evidence["errors"],
        )

    def test_message_listener_adapter_registration_is_framework_callback_topology(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "src"
            adapter = (
                source / "org/springframework/amqp/rabbit/listener/adapter/"
                "MessageListenerAdapter.java"
            )
            receiver = source / "sample/Receiver.java"
            application = source / "sample/Application.java"
            for path in (adapter, receiver, application):
                path.parent.mkdir(parents=True, exist_ok=True)
            adapter.write_text(
                "package org.springframework.amqp.rabbit.listener.adapter; "
                "public class MessageListenerAdapter { "
                "public MessageListenerAdapter(Object target, String method) {} }",
                encoding="utf-8",
            )
            receiver.write_text(
                "package sample; import java.util.concurrent.CountDownLatch; "
                "public class Receiver { public void handlePayload(String value) { "
                "new CountDownLatch(1).countDown(); } }",
                encoding="utf-8",
            )
            application.write_text(
                "package sample; import org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter; "
                "public class Application { MessageListenerAdapter listenerAdapter(Receiver receiver) { "
                "return new MessageListenerAdapter(receiver, \"handlePayload\"); } "
                "public static void main(String[] args) {} }",
                encoding="utf-8",
            )
            classes = root / "classes"
            _compile(classes, [adapter, receiver, application])
            artifact = root / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nStart-Class: sample.Application\n",
                )
                for class_file in sorted(classes.rglob("*.class")):
                    relative = class_file.relative_to(classes).as_posix()
                    if relative.startswith("sample/"):
                        archive.write(class_file, "BOOT-INF/classes/" + relative)
            changed_rows = [{
                "coord": "jdk:java.base",
                "api_name": "java.util.concurrent.CountDownLatch.countDown",
                "api_signature": "()",
                "symbol_kind": "method",
            }]

            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact, changed_rows, {}
            )
            observed = topology_coverage.classify_topologies(
                evidence["edges"], evidence["artifact_layout"]
            )

        self.assertTrue(evidence["complete"], evidence["errors"])
        self.assertIn("framework_callback", observed)
        callback = evidence["artifact_layout"]["framework_callback_links"][0]
        self.assertEqual(callback["callback"], [
            "sample.Receiver", "handlePayload", "(Ljava/lang/String;)V",
        ])
        self.assertEqual(callback["registration_instruction_offset"], 7)
        self.assertEqual(callback["start_class"], "sample.Application")

    def test_packaged_command_line_runner_activation_is_framework_callback_topology(self):
        target = ("vendor.Api", "call", "()V")
        inventory = {
            "resources": {
                "META-INF/MANIFEST.MF": (
                    b"Manifest-Version: 1.0\nStart-Class: sample.Application\n"
                ),
            },
            "classes": {
                "BOOT-INF/classes/sample/Application.class": b"application",
                "BOOT-INF/classes/sample/StartupTask.class": b"runner",
            },
        }
        edges = [
            {
                "artifact_entry": "BOOT-INF/classes/sample/StartupTask.class",
                "caller_owner": "sample.StartupTask",
                "caller_member": "run",
                "caller_descriptor": "([Ljava/lang/String;)V",
                "callee_owner": target[0],
                "callee_member": target[1],
                "callee_descriptor": target[2],
            },
        ]
        verbose_runner = """
class sample.StartupTask implements org.springframework.boot.CommandLineRunner
RuntimeVisibleAnnotations:
  0: #1()
    org.springframework.stereotype.Component
"""
        application_javap = """
public class sample.Application {
  public static void main(java.lang.String[]);
    descriptor: ([Ljava/lang/String;)V
    Code:
         0: invokestatic  #1  // Method org/springframework/boot/SpringApplication.run:(Ljava/lang/Class;[Ljava/lang/String;)Lorg/springframework/context/ConfigurableApplicationContext;
}
"""

        def javap_output(content, *_args):
            return application_javap if content == b"application" else verbose_runner

        with mock.patch.object(
            topology_coverage,
            "_javap_text",
            side_effect=javap_output,
        ):
            callbacks = topology_coverage._framework_callback_evidence(
                inventory, {target}, edges
            )
        with mock.patch.object(
            topology_coverage,
            "_javap_text",
            side_effect=lambda content, *_args: (
                application_javap if content == b"application" else
                "class sample.StartupTask implements "
                "org.springframework.boot.CommandLineRunner\n"
            ),
        ):
            unregistered_callbacks = topology_coverage._framework_callback_evidence(
                inventory, {target}, edges
            )
        observed = topology_coverage.classify_topologies([], {
            "authority": "final_artifact_edge_oracle",
            "complete": True,
            "target_apis": [{
                "owner": target[0], "member": target[1], "descriptor": target[2],
            }],
            "entry_layout": [],
            "framework_callback_links": callbacks,
        })

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(callbacks[0]["start_class"], "sample.Application")
        self.assertEqual(callbacks[0]["callback"], [
            "sample.StartupTask", "run", "([Ljava/lang/String;)V",
        ])
        self.assertEqual(callbacks[0]["targets"], [list(target)])
        self.assertEqual(unregistered_callbacks, [])
        self.assertIn("framework_callback", observed)

    def test_source_conflict_requires_verified_provenance_and_explicit_normalization(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            source_root, source_attestation = self._source_attestation(root, artifact, expectations)
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
                source_root=source_root,
                source_attestation=source_attestation,
            )

        layout = evidence["artifact_layout"]
        layout["source_provenance"]["artifact_sha256"] = "0" * 64
        observed = topology_coverage.classify_topologies(evidence["edges"], layout)

        self.assertNotIn("source_bytecode_agree", observed)
        self.assertNotIn("source_bytecode_true_conflict", observed)

    def test_mixed_root_layout_requires_exact_owner_entry_mapping(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, expectations = self._build_fixture(Path(temp_dir))
            selected = self._selected_api_rows(expectations)
            exact_entries = {
                "topology.target.TargetApi": ["BOOT-INF/lib/target.jar!/topology/target/TargetApi.class"],
                "topology.target.TargetInterface": ["BOOT-INF/lib/target.jar!/topology/target/TargetInterface.class"],
                "topology.target.SameJarBridge": ["BOOT-INF/lib/target.jar!/topology/target/SameJarBridge.class"],
            }
            positive = topology_coverage.extract_artifact_topology_evidence(
                artifact, selected, {}, target_owner_entries=exact_entries,
            )
            negative = topology_coverage.extract_artifact_topology_evidence(
                artifact, selected, {},
            )

        roles = {item.get("entry"): item["role"] for item in positive["artifact_layout"]["entry_layout"] if item.get("entry")}
        prefix_roles = {
            item.get("prefix"): item["role"]
            for item in positive["artifact_layout"]["entry_layout"]
            if item.get("prefix")
        }
        self.assertEqual(roles["BOOT-INF/classes/topology/business/App.class"], "business")
        self.assertEqual(prefix_roles["BOOT-INF/lib/target.jar!/"], "target")
        self.assertFalse(negative["complete"])

    def test_virtual_dispatch_requires_parsed_target_hierarchy_relation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, expectations = self._build_fixture(Path(temp_dir))
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact, self._selected_api_rows(expectations),
                {"topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                 "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"]},
            )

        observed = topology_coverage.classify_topologies(evidence["edges"], evidence["artifact_layout"])
        self.assertIn("virtual_dispatch", observed)
        evidence["artifact_layout"]["hierarchy_evidence"] = [
            {"child": "java.lang.String", "parent": "java.lang.Object", "authority": "javap_class_header"}
        ]
        self.assertNotIn("virtual_dispatch", topology_coverage.classify_topologies(evidence["edges"], evidence["artifact_layout"]))

    def test_class_header_parents_erases_generics_and_keeps_every_interface(self):
        completed = subprocess.CompletedProcess(
            ["javap"],
            0,
            stdout=(
                "public class sample.Impl extends sample.Base<java.lang.String> "
                "implements sample.First<java.lang.String, java.lang.Integer>, "
                "sample.Second<java.util.Map<java.lang.String, java.lang.Integer>>, "
                "sample.Third {\n"
            ),
            stderr="",
        )

        with mock.patch.object(topology_coverage.subprocess, "run", return_value=completed):
            parents, error = topology_coverage._class_header_parents(b"class", 1.0)

        self.assertEqual(error, "")
        self.assertEqual(
            parents,
            ("sample.Base", "sample.First", "sample.Second", "sample.Third"),
        )

    def test_hierarchy_scan_reuses_sha_headers_with_sequential_equivalent_relations(self):
        inventory = {
            "classes": {
                "sample/Impl.class": b"impl",
                "sample/Contract.class": b"contract",
                "BOOT-INF/lib/duplicate.jar!/sample/Impl.class": b"impl",
                "BOOT-INF/lib/duplicate.jar!/sample/Contract.class": b"contract",
            },
            "resources": {},
            "containers": {"BOOT-INF/lib/duplicate.jar"},
        }
        calls = []

        def read_header(content, timeout_sec):
            calls.append((content, timeout_sec))
            if content == b"impl":
                return ("sample.Contract",), ""
            return (), ""

        with mock.patch.object(topology_coverage, "_class_header_parents", side_effect=read_header):
            scan = topology_coverage._scan_class_hierarchy(
                inventory, timeout_sec=1.0, max_workers=2,
            )

        expected = [
            {
                "child_entry": "BOOT-INF/lib/duplicate.jar!/sample/Impl.class",
                "child": "sample.Impl",
                "parent_entry": "BOOT-INF/lib/duplicate.jar!/sample/Contract.class",
                "parent": "sample.Contract",
                "authority": "javap_class_header",
            },
            {
                "child_entry": "sample/Impl.class",
                "child": "sample.Impl",
                "parent_entry": "sample/Contract.class",
                "parent": "sample.Contract",
                "authority": "javap_class_header",
            },
        ]
        self.assertEqual(scan["relations"], expected)
        self.assertEqual(scan["errors"], [])
        self.assertEqual(len(calls), 2)
        self.assertEqual(scan["metrics"]["class_entries"], 4)
        self.assertEqual(scan["metrics"]["unique_class_headers"], 2)
        self.assertEqual(scan["metrics"]["cache_hits"], 2)

    def test_hierarchy_scan_retains_every_header_failure(self):
        inventory = {
            "classes": {
                "sample/First.class": b"bad-first",
                "sample/Second.class": b"bad-second",
                "sample/Duplicate.class": b"bad-first",
            },
            "resources": {},
            "containers": set(),
        }

        def read_header(content, timeout_sec):
            return (), f"cannot read {content.decode('ascii')}"

        with mock.patch.object(topology_coverage, "_class_header_parents", side_effect=read_header):
            scan = topology_coverage._scan_class_hierarchy(inventory, timeout_sec=1.0)

        self.assertFalse(scan["complete"])
        self.assertEqual(len(scan["errors"]), 3)
        self.assertTrue(any("sample/First.class" in error and "bad-first" in error for error in scan["errors"]))
        self.assertTrue(any("sample/Second.class" in error and "bad-second" in error for error in scan["errors"]))
        self.assertTrue(any("sample/Duplicate.class" in error and "bad-first" in error for error in scan["errors"]))

    def test_hierarchy_scan_cache_is_isolated_between_artifacts(self):
        inventory = {
            "classes": {"sample/Contract.class": b"shared"},
            "resources": {},
            "containers": set(),
        }
        calls = []

        def read_header(content, timeout_sec):
            calls.append(content)
            return (), ""

        with mock.patch.object(topology_coverage, "_class_header_parents", side_effect=read_header):
            topology_coverage._scan_class_hierarchy(inventory, timeout_sec=1.0)
            topology_coverage._scan_class_hierarchy(inventory, timeout_sec=1.0)

        self.assertEqual(calls, [b"shared", b"shared"])

    def test_hierarchy_scan_deadline_fails_closed_and_exposes_metrics(self):
        inventory = {
            "classes": {"sample/Slow.class": b"slow"},
            "resources": {},
            "containers": set(),
        }

        def read_header(content, timeout_sec):
            time.sleep(0.1)
            return (), ""

        with (
            mock.patch.object(topology_coverage, "scan_final_artifact", return_value={
                "edges": [], "complete": True, "artifact_sha256": "a" * 64, "failures": [],
            }),
            mock.patch.object(topology_coverage, "_archive_inventory", return_value=inventory),
            mock.patch.object(topology_coverage, "_class_header_parents", side_effect=read_header),
        ):
            evidence = topology_coverage.extract_artifact_topology_evidence(
                Path("ignored.jar"), [], {}, hierarchy_scan_timeout_sec=0.01,
            )

        self.assertFalse(evidence["complete"])
        self.assertTrue(any("deadline exceeded" in error for error in evidence["errors"]))
        metrics = evidence["artifact_layout"]["hierarchy_scan"]
        self.assertEqual(metrics["class_entries"], 1)
        self.assertEqual(metrics["timed_out_class_entries"], 1)
        self.assertGreaterEqual(metrics["elapsed_sec"], 0.0)

    def test_hierarchy_scan_deadline_joins_active_workers_before_returning(self):
        inventory = {
            "classes": {"sample/Slow.class": b"slow"},
            "resources": {},
            "containers": set(),
        }
        worker_started = threading.Event()
        worker_finished = threading.Event()
        release_worker = threading.Event()

        def read_header(content, timeout_sec):
            worker_started.set()
            release_worker.wait(timeout=1.0)
            worker_finished.set()
            return (), ""

        def release_after_deadline():
            worker_started.wait(timeout=1.0)
            time.sleep(0.03)
            release_worker.set()

        releaser = threading.Thread(target=release_after_deadline)
        releaser.start()
        try:
            with mock.patch.object(topology_coverage, "_class_header_parents", side_effect=read_header):
                scan = topology_coverage._scan_class_hierarchy(
                    inventory, timeout_sec=0.01, max_workers=1,
                )

            self.assertTrue(worker_started.is_set())
            self.assertTrue(worker_finished.is_set())
            self.assertFalse(scan["complete"])
            self.assertTrue(any("deadline exceeded" in error for error in scan["errors"]))
        finally:
            release_worker.set()
            releaser.join(timeout=1.0)

    def test_hierarchy_scan_returns_incomplete_error_when_wait_is_interrupted(self):
        inventory = {
            "classes": {"sample/Impl.class": b"impl"},
            "resources": {},
            "containers": set(),
        }

        with (
            mock.patch.object(topology_coverage, "_class_header_parents", return_value=((), "")),
            mock.patch.object(topology_coverage, "wait", side_effect=KeyboardInterrupt("stop")),
        ):
            scan = topology_coverage._scan_class_hierarchy(inventory, timeout_sec=1.0)

        self.assertFalse(scan["complete"])
        self.assertEqual(len(scan["errors"]), 1)
        self.assertIn("hierarchy scan interrupted: KeyboardInterrupt", scan["errors"][0])

    def test_hierarchy_scan_returns_incomplete_error_when_worker_exits(self):
        inventory = {
            "classes": {"sample/Impl.class": b"impl"},
            "resources": {},
            "containers": set(),
        }

        with mock.patch.object(
            topology_coverage,
            "_class_header_parents",
            side_effect=SystemExit("stop"),
        ):
            scan = topology_coverage._scan_class_hierarchy(inventory, timeout_sec=1.0)

        self.assertFalse(scan["complete"])
        self.assertEqual(len(scan["errors"]), 1)
        self.assertIn("header worker failed: SystemExit", scan["errors"][0])

    def test_stale_source_tree_and_fake_revision_reject_source_ids(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            source_root, source_attestation = self._source_attestation(root, artifact, expectations)
            payload = json.loads(source_attestation.read_text(encoding="utf-8"))
            evidence_path = Path(payload["evidence_path"])
            original_evidence = evidence_path.read_bytes()
            evidence_path.write_bytes(original_evidence + b"\n")
            tampered = topology_coverage.extract_artifact_topology_evidence(
                artifact, self._selected_api_rows(expectations),
                {"topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                 "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"]},
                source_root=source_root, source_attestation=source_attestation,
            )
            evidence_path.write_bytes(original_evidence)
            payload["git_revision"] = "b" * 40
            source_attestation.write_text(json.dumps(payload), encoding="utf-8")
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact, self._selected_api_rows(expectations),
                {"topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                 "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"]},
                source_root=source_root, source_attestation=source_attestation,
            )

        observed = topology_coverage.classify_topologies(evidence["edges"], evidence["artifact_layout"])
        tampered_observed = topology_coverage.classify_topologies(
            tampered["edges"], tampered["artifact_layout"]
        )
        self.assertNotIn("source_bytecode_agree", tampered_observed)
        self.assertNotIn("source_bytecode_agree", observed)
        self.assertNotIn("source_bytecode_true_conflict", observed)

    def test_source_attestation_rejects_dirty_tree_even_when_self_hash_is_recomputed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            source_root, source_attestation = self._source_attestation(root, artifact, expectations)
            source_file = source_root / "src" / "business" / "topology" / "business" / "App.java"
            source_file.write_text(
                source_file.read_text(encoding="utf-8") + "\n// substituted live source\n",
                encoding="utf-8",
            )
            payload = json.loads(source_attestation.read_text(encoding="utf-8"))
            payload["source_tree_sha256"] = topology_coverage.compute_source_tree_sha256(
                source_root / "src"
            )
            source_attestation.write_text(json.dumps(payload), encoding="utf-8")
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
                source_root=source_root,
                source_attestation=source_attestation,
            )

        self.assertFalse(evidence["artifact_layout"]["source_provenance"]["valid"])
        observed = topology_coverage.classify_topologies(evidence["edges"], evidence["artifact_layout"])
        self.assertNotIn("source_bytecode_agree", observed)
        self.assertNotIn("source_bytecode_true_conflict", observed)

    def test_source_attestation_rejects_substituted_path_outside_declared_revision_tree(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact, expectations = self._build_fixture(root)
            source_root, source_attestation = self._source_attestation(root, artifact, expectations)
            substituted = root / "substituted"
            shutil.copytree(source_root / "src", substituted)
            payload = json.loads(source_attestation.read_text(encoding="utf-8"))
            payload["source_path"] = "../substituted"
            payload["source_tree_sha256"] = topology_coverage.compute_source_tree_sha256(substituted)
            source_attestation.write_text(json.dumps(payload), encoding="utf-8")
            evidence = topology_coverage.extract_artifact_topology_evidence(
                artifact,
                self._selected_api_rows(expectations),
                {
                    "topology:library": ["BOOT-INF/lib/target.jar", "BOOT-INF/lib/samecoord.jar"],
                    "topology:crossjar": ["BOOT-INF/lib/crossjar.jar"],
                },
                source_root=source_root,
                source_attestation=source_attestation,
            )

        observed = topology_coverage.classify_topologies(evidence["edges"], evidence["artifact_layout"])
        self.assertNotIn("source_bytecode_agree", observed)
        self.assertNotIn("source_bytecode_true_conflict", observed)

    def test_true_conflict_uses_distinct_source_and_packaged_java_fixtures(self):
        source_text = (FIXTURE / "src" / "source" / "topology" / "business" / "ConflictCaller.java").read_text(encoding="utf-8")
        bytecode_text = (FIXTURE / "src" / "bytecode" / "topology" / "business" / "ConflictCaller.java").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact, layout = self._build_fixture(Path(temp_dir))
            edges = oracle.scan_final_artifact(artifact)["edges"]

        conflict = layout["source_conflicts"][0]
        self.assertIn('overloaded("source")', source_text)
        self.assertIn("overloaded(7)", bytecode_text)
        self.assertTrue(any(
            all(row.get(key) == value for key, value in conflict["bytecode_edge"].items())
            for row in edges
        ))

    def test_compute_coverage_sorts_deduplicates_and_marks_discovery_eligibility(self):
        coverage = topology_coverage.compute_topology_coverage(
            ("spi", "business_direct", "spi"),
            {"business_direct", "virtual_dispatch"},
            prior_covered={"business_direct"},
            case_mode="discovery",
        )

        self.assertEqual(coverage["required"], ["business_direct", "spi"])
        self.assertEqual(coverage["observed"], ["business_direct", "virtual_dispatch"])
        self.assertEqual(coverage["missing"], ["spi"])
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["newly_observed"], ["virtual_dispatch"])
        self.assertTrue(coverage["discovery_target_eligible"])
        self.assertFalse(
            topology_coverage.compute_topology_coverage(
                ("business_direct",), {"business_direct"},
                prior_covered={"business_direct"}, case_mode="discovery",
            )["discovery_target_eligible"]
        )
        self.assertFalse(
            topology_coverage.compute_topology_coverage(
                ("business_direct",), {"business_direct"}, case_mode="guard"
            )["discovery_target_eligible"]
        )


if __name__ == "__main__":
    unittest.main()
