import hashlib
import inspect
import json
import shutil
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import framework_adapters as framework_adapter_module
from framework_adapters import (
    run_framework_adapters as _run_framework_adapters,
    run_mybatis_proxy_adapter as _run_mybatis_proxy_adapter,
    serialize_framework_batches,
)
from step5_evidence_ingestion import ingest_collector_batches
from step5_artifact_fact_store import FactOutcome, Step5ArtifactFactStore
from step5_evidence_model import (
    ActivationEvidence,
    CollectedEdge,
    CollectorBatch,
    CoverageRecord,
    EvidenceAuthority,
    EvidenceConcern,
    EvidenceFailure,
)


def run_framework_adapters(*args, **kwargs):
    """Keep legacy behavior checks on the v1 serializer, not the batch API."""
    return serialize_framework_batches(_run_framework_adapters(*args, **kwargs))


def run_mybatis_proxy_adapter(*args, **kwargs):
    return serialize_framework_batches((_run_mybatis_proxy_adapter(*args, **kwargs),))["adapters"][0]


def ingest_framework_payload(graph, payload):
    """Build typed framework batches for projection-focused legacy fixtures."""
    batches = tuple(
        framework_adapter_module._framework_batch(
            adapter["adapter"],
            adapter["version"],
            adapter.get("status", "complete"),
            (),
            adapter.get("edges", ()),
            (),
            (),
            {},
        )
        for adapter in payload.get("adapters", ())
    )
    result = ingest_collector_batches(graph, batches)
    return {
        key: getattr(result, key)
        for key in (
            "matched_callback_edges",
            "unmatched_callback_edges",
            "framework_entry_methods",
            "runtime_framework_entry_methods",
            "framework_activation_linked_methods",
            "framework_proxy_dispatch_edges",
            "framework_mybatis_proxy_dispatch_edges",
            "framework_transaction_proxy_edges",
            "ambiguous_framework_proxy_dispatches",
        )
    }


class FrameworkAdaptersTest(unittest.TestCase):
    ADAPTER_ENTRY_POINTS = (
        "run_spi_adapter",
        "run_spring_adapter",
        "run_runtime_spring_registration_adapter",
        "run_spring_transaction_proxy_adapter",
        "run_spring_data_repository_adapter",
        "run_mybatis_adapter",
        "run_mybatis_proxy_adapter",
        "run_dynamic_proxy_adapter",
        "run_declarative_http_client_adapter",
    )

    def test_runtime_spring_registration_shared_facts_preserve_exact_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime.jar"
            business = root / "business.jar"
            with zipfile.ZipFile(runtime, "w") as archive:
                archive.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=com.acme.Listener\n",
                )
            with zipfile.ZipFile(business, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/com/acme/Application.class", b"application",
                )
            catalog = {"entries": [
                {
                    "coord": "com.acme:runtime",
                    "jar_path": str(runtime),
                    "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
                },
                {
                    "coord": "__business__",
                    "jar_path": str(business),
                    "sha256": hashlib.sha256(business.read_bytes()).hexdigest(),
                },
            ]}
            activation = ([{
                "file": "/src/Application.java",
                "spring_application_run": True,
                "spring_boot_annotation": True,
                "business_entry": "com.acme.Application.main",
            }], [])
            with patch.object(
                framework_adapter_module,
                "_spring_boot_business_activation",
                return_value=activation,
            ):
                legacy = framework_adapter_module.run_runtime_spring_registration_adapter(
                    [], artifact_catalog=catalog,
                )
                shared = framework_adapter_module.run_runtime_spring_registration_adapter(
                    [], artifact_catalog=catalog,
                    fact_store=Step5ArtifactFactStore.from_catalog(catalog),
                )

            self.assertEqual(
                serialize_framework_batches((legacy,)),
                serialize_framework_batches((shared,)),
            )

    def test_all_nine_public_adapters_return_immutable_typed_batches(self):
        for name in self.ADAPTER_ENTRY_POINTS:
            with self.subTest(adapter=name):
                entry_point = getattr(framework_adapter_module, name)
                self.assertIn("artifact_catalog", inspect.signature(entry_point).parameters)

                batch = entry_point([], artifact_catalog={"entries": []})

                self.assertIsInstance(batch, CollectorBatch)
                self.assertTrue(batch.collector)
                self.assertTrue(batch.version)
                self.assertIsInstance(batch.edges, tuple)
                self.assertTrue(all(isinstance(edge, CollectedEdge) for edge in batch.edges))
                self.assertIsInstance(batch.failures, tuple)
                self.assertTrue(all(isinstance(item, EvidenceFailure) for item in batch.failures))
                self.assertIsInstance(batch.concerns, tuple)
                self.assertTrue(all(isinstance(item, EvidenceConcern) for item in batch.concerns))
                self.assertIsInstance(batch.coverage, tuple)
                self.assertTrue(all(isinstance(item, CoverageRecord) for item in batch.coverage))
                self.assertEqual(len(batch.coverage), 1)
                self.assertEqual(batch.coverage[0].status, "not_applicable")
                self.assertFalse(batch.coverage[0].applicable)
                self.assertIsInstance(batch.metrics, tuple)
                with self.assertRaises((AttributeError, TypeError)):
                    batch.collector = "mutated"

    def test_framework_batch_is_deeply_immutable_and_keeps_typed_artifact_provenance(self):
        raw_edge = {
            "source": "com.acme.Repository.find",
            "target": "framework.Proxy.invoke()",
            "edge_kind": "spring_data_repository_proxy_dispatch",
            "confidence": "high",
            "conditions": ["repository_registered"],
            "provenance": {
                "authority": "final_artifact_javap",
                "file": "/src/Repository.java",
                "jar": "/artifact/application.jar",
                "artifact_sha256": "a" * 64,
                "artifact_entry": "BOOT-INF/classes/com/acme/Repository.class",
                "nested": {"verified": True},
            },
        }
        nodes = [{"id": "repository", "details": {"active": True}}]
        batch = framework_adapter_module._framework_batch(
            "spring_data_repository_proxy", "1", "complete",
            nodes, [raw_edge], [], [], {},
        )
        before = serialize_framework_batches((batch,))

        raw_edge["target"] = "mutated.Target.invoke()"
        raw_edge["provenance"]["nested"]["verified"] = False
        nodes[0]["details"]["active"] = False
        after = serialize_framework_batches((batch,))

        self.assertEqual(after, before)
        typed = batch.edges[0]
        self.assertEqual(typed.callee_symbol, "framework.Proxy.invoke()")
        self.assertEqual(typed.provenance.artifact_path, "/artifact/application.jar")
        self.assertEqual(typed.provenance.artifact_sha256, "a" * 64)
        self.assertEqual(
            typed.provenance.artifact_entry,
            "BOOT-INF/classes/com/acme/Repository.class",
        )

    def test_framework_batch_preserves_typed_composite_activation_proof(self):
        raw_edge = {
            "source": "framework:spring-aop",
            "target": "com.acme.AuditAspect.before()V",
            "edge_kind": "spring_aop_activation",
            "confidence": "high",
            "activation_verified": True,
            "activation_evidence": [{
                "authority": "current_final_artifact",
                "proof_kind": "runtime_visible_aspect_registration",
                "source": "BOOT-INF/classes/com/acme/AuditAspect.class",
                "artifact_sha256": "a" * 64,
                "detail": "com.acme.AuditAspect.before()V",
            }],
            "provenance": {
                "artifact_sha256": "a" * 64,
                "artifact_entry": "BOOT-INF/classes/com/acme/AuditAspect.class",
            },
        }

        batch = framework_adapter_module._framework_batch(
            "spring_aop_activation", "1", "complete", (), [raw_edge], (), (), {}
        )
        mapping = batch.to_mapping()

        self.assertTrue(batch.edges[0].activation_verified)
        self.assertIsInstance(batch.edges[0].activation_evidence[0], ActivationEvidence)
        self.assertEqual(
            mapping["edges"][0]["activation_evidence"][0]["proof_kind"],
            "runtime_visible_aspect_registration",
        )

    def test_mybatis_runtime_dispatch_requires_exact_jvm_descriptors(self):
        wrong_outputs = {
            "org.apache.ibatis.binding.MapperProxy": (
                "InterfaceMethod org/apache/ibatis/binding/MapperProxy$MapperMethodInvoker."
                "invoke:(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;"
                "Lorg/apache/ibatis/session/SqlSession;)V"
            ),
            "org.apache.ibatis.binding.MapperProxy$PlainMethodInvoker": (
                "Method org/apache/ibatis/binding/MapperMethod.execute:"
                "(Lorg/apache/ibatis/session/SqlSession;[Ljava/lang/Object;)V"
            ),
            "org.apache.ibatis.binding.MapperMethod": (
                "InterfaceMethod org/apache/ibatis/session/SqlSession.selectOne:"
                "(Ljava/lang/String;Ljava/lang/Object;)V"
            ),
        }

        def completed(command, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=wrong_outputs[command[-1]])

        with patch.object(framework_adapter_module.subprocess, "run", side_effect=completed):
            verified, errors = framework_adapter_module._verify_mybatis_runtime_dispatch({
                "jar_path": "/artifact/mybatis.jar",
            })

        self.assertEqual(errors, [])
        self.assertEqual(verified, {
            "proxy_entry_dispatch": False,
            "plain_invoker_dispatch": False,
            "select_one_dispatch": False,
        })

    def test_mybatis_runtime_dispatch_shares_exact_javap_output(self):
        owners = (
            "org.apache.ibatis.binding.MapperProxy",
            "org.apache.ibatis.binding.MapperProxy$PlainMethodInvoker",
            "org.apache.ibatis.binding.MapperMethod",
        )
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "mybatis.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                for owner in owners:
                    archive.writestr(owner.replace(".", "/") + ".class", b"fixture")
            entry = {
                "coord": "org.mybatis:mybatis",
                "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})
            completed = SimpleNamespace(returncode=0, stdout="fixture-output")
            with patch.object(
                framework_adapter_module.subprocess, "run", return_value=completed,
            ) as run:
                first = framework_adapter_module._verify_mybatis_runtime_dispatch(
                    entry, fact_store=store,
                )
                second = framework_adapter_module._verify_mybatis_runtime_dispatch(
                    entry, fact_store=store,
                )

            self.assertEqual(first, second)
            self.assertEqual(3, run.call_count)
            self.assertEqual(3, store.metrics()["javap_starts"])
            self.assertEqual(3, store.metrics()["javap_shared_hits"])

    def test_mybatis_runtime_dispatch_does_not_bypass_fact_store_identity_failure(self):
        owners = (
            "org.apache.ibatis.binding.MapperProxy",
            "org.apache.ibatis.binding.MapperProxy$PlainMethodInvoker",
            "org.apache.ibatis.binding.MapperMethod",
        )
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "mybatis.jar"
            replacement = Path(tmp) / "replacement.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                for owner in owners:
                    archive.writestr(owner.replace(".", "/") + ".class", b"original")
            digest = hashlib.sha256(jar.read_bytes()).hexdigest()
            entry = {
                "coord": "org.mybatis:mybatis", "jar_path": str(jar),
                "sha256": digest,
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})
            store.inventory(entry["coord"])
            with zipfile.ZipFile(replacement, "w") as archive:
                for owner in owners:
                    archive.writestr(owner.replace(".", "/") + ".class", b"replacement")
            replacement.replace(jar)

            completed = SimpleNamespace(returncode=0, stdout="")
            with patch.object(
                framework_adapter_module.subprocess, "run", return_value=completed,
            ) as run:
                verified, errors = framework_adapter_module._verify_mybatis_runtime_dispatch(
                    entry, fact_store=store,
                )
            runtime_entry, runtime_errors, count = framework_adapter_module._mybatis_runtime_entry(
                {"entries": [{**entry, "evidence_source": "current_final_artifact"}]},
                fact_store=store,
            )

        self.assertFalse(any(verified.values()))
        self.assertEqual(0, run.call_count)
        self.assertEqual(len(errors), 3)
        self.assertTrue(all("artifact_changed_after_inventory" in item for item in errors))

        self.assertIsNone(runtime_entry)
        self.assertEqual(0, count)
        self.assertEqual(len(runtime_errors), 1)
        self.assertIn("artifact_fact_store_identity_failed", runtime_errors[0])

    def test_mybatis_runtime_dispatch_does_not_bypass_missing_shared_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "mybatis.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr(
                    "org/apache/ibatis/binding/MapperProxy.class", b"fixture",
                )
            entry = {
                "coord": "org.mybatis:mybatis",
                "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})

            completed = SimpleNamespace(returncode=0, stdout="")
            with patch.object(
                framework_adapter_module.subprocess, "run", return_value=completed,
            ) as run:
                verified, errors = framework_adapter_module._verify_mybatis_runtime_dispatch(
                    entry, fact_store=store,
                )

        self.assertFalse(any(verified.values()))
        self.assertEqual(1, run.call_count)
        self.assertEqual(2, len(errors))
        self.assertTrue(all("shared_class_missing" in item for item in errors))

    def test_artifact_javap_does_not_run_after_fact_store_identity_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "runtime.jar"
            replacement = Path(tmp) / "replacement.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("com/acme/Target.class", b"original")
            digest = hashlib.sha256(jar.read_bytes()).hexdigest()
            entry = {"coord": "g:a", "jar_path": str(jar), "sha256": digest}
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})
            store.inventory("g:a")
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("com/acme/Target.class", b"replacement")
            replacement.replace(jar)

            with patch.object(framework_adapter_module.subprocess, "run") as run:
                completed, error = framework_adapter_module._artifact_javap(
                    entry, "com.acme.Target", ("-p", "-s"),
                    "test-profile", store,
                )

        self.assertIsNone(completed)
        self.assertIn("artifact_fact_store_identity_failed", error)
        self.assertEqual(0, run.call_count)

    def test_fact_store_identity_failure_is_typed_and_blocking(self):
        failure = framework_adapter_module._framework_failure(
            "spring_data_repository_proxy",
            "/runtime.jar:artifact_fact_store_identity_failed:artifact_changed_after_inventory",
        )

        self.assertEqual("ARTIFACT_FACT_STORE_IDENTITY_FAILED", failure.reason_code)
        self.assertTrue(failure.blocking)

    def test_runtime_spring_registration_blocks_changed_fact_store_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "spring-runtime.jar"
            replacement = Path(tmp) / "replacement.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=com.acme.Listener\n",
                )
            entry = {
                "coord": "com.acme:spring-runtime",
                "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            catalog = {"entries": [entry]}
            store = Step5ArtifactFactStore.from_catalog(catalog)
            store.inventory(entry["coord"])
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=com.acme.Replaced\n",
                )
            replacement.replace(jar)

            batch = framework_adapter_module.run_runtime_spring_registration_adapter(
                [], artifact_catalog=catalog, fact_store=store,
            )

        self.assertFalse(batch.edges)
        self.assertEqual(
            {failure.reason_code for failure in batch.failures},
            {"ARTIFACT_FACT_STORE_IDENTITY_FAILED"},
        )
        self.assertTrue(all(failure.blocking for failure in batch.failures))

    def test_runtime_spring_registration_preserves_resource_identity_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "spring-runtime.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=com.acme.Listener\n",
                )
            entry = {
                "coord": "com.acme:spring-runtime",
                "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            catalog = {"entries": [entry]}
            store = Step5ArtifactFactStore.from_catalog(catalog)
            with patch.object(
                store, "resource_bytes",
                return_value=FactOutcome(
                    "failed", None,
                    "ValueError: artifact_changed_after_inventory", "zipfile",
                ),
            ):
                batch = framework_adapter_module.run_runtime_spring_registration_adapter(
                    [], artifact_catalog=catalog, fact_store=store,
                )

        self.assertFalse(batch.edges)
        self.assertEqual(
            {failure.reason_code for failure in batch.failures},
            {"ARTIFACT_FACT_STORE_IDENTITY_FAILED"},
        )
        self.assertTrue(all(failure.blocking for failure in batch.failures))

    def test_runtime_spring_registration_blocks_deleted_shared_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "spring-runtime.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=com.acme.Listener\n",
                )
            entry = {
                "coord": "com.acme:spring-runtime",
                "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            catalog = {"entries": [entry]}
            store = Step5ArtifactFactStore.from_catalog(catalog)
            store.inventory(entry["coord"])
            jar.unlink()

            batch = framework_adapter_module.run_runtime_spring_registration_adapter(
                [], artifact_catalog=catalog, fact_store=store,
            )

        self.assertFalse(batch.edges)
        self.assertEqual(
            {failure.reason_code for failure in batch.failures},
            {"ARTIFACT_FACT_STORE_IDENTITY_FAILED"},
        )
        self.assertTrue(all(failure.blocking for failure in batch.failures))

    def test_message_listener_does_not_scan_changed_fact_store_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "business.jar"
            replacement = Path(tmp) / "replacement.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("com/acme/Application.class", b"original")
            entry = {
                "coord": "__business__",
                "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})
            store.inventory(entry["coord"])
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("com/acme/Application.class", b"replacement")
            replacement.replace(jar)

            with patch.object(framework_adapter_module.subprocess, "run") as run:
                callbacks, errors = (
                    framework_adapter_module._message_listener_adapter_callbacks(
                        str(jar), entry["coord"], [], fact_store=store, entry=entry,
                    )
                )

        self.assertEqual([], callbacks)
        self.assertEqual(0, run.call_count)
        self.assertEqual(1, len(errors))
        self.assertIn("artifact_fact_store_identity_failed", errors[0])

    def test_framework_orchestrator_returns_tuple_and_serializer_alone_projects_v1(self):
        batches = _run_framework_adapters([], artifact_catalog={"entries": []})

        self.assertIsInstance(batches, tuple)
        self.assertEqual(len(batches), 11)
        self.assertTrue(all(isinstance(batch, CollectorBatch) for batch in batches))
        serializer = getattr(framework_adapter_module, "serialize_framework_batches", None)
        self.assertTrue(callable(serializer))
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "framework-adapters.json"
            payload = serializer(batches, str(output))
            persisted = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload, persisted)
        self.assertEqual(
            payload["schema"], "java-upgrade-analyzer.framework-adapters.v1"
        )
        self.assertEqual(
            [item["adapter"] for item in payload["adapters"]],
            [batch.collector for batch in batches],
        )
        self.assertTrue(all(item["status"] == "not_applicable" for item in payload["adapters"]))

    def test_framework_semantic_edges_never_claim_physical_final_artifact_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            java = Path(tmp) / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Runner.java").write_text(
                "package com.acme; class Runner implements "
                "org.springframework.boot.CommandLineRunner { "
                "public void run(String... args) {} }",
                encoding="utf-8",
            )

            batch = framework_adapter_module.run_spring_adapter([
                {"root": str(Path(tmp) / "src/main/java"), "owner_type": "business"}
            ])

        self.assertIsInstance(batch, CollectorBatch)
        self.assertTrue(batch.edges)
        self.assertTrue(all(edge.semantic for edge in batch.edges))
        self.assertTrue(all(
            edge.provenance.authority in {
                EvidenceAuthority.FRAMEWORK_SEMANTIC,
                EvidenceAuthority.RESOURCE_CONFIGURATION,
                EvidenceAuthority.SOURCE_AST,
            }
            for edge in batch.edges
        ))
        self.assertTrue(all(
            edge.provenance.authority != EvidenceAuthority.CURRENT_FINAL_ARTIFACT
            for edge in batch.edges
        ))

    def test_malformed_spring_xml_is_a_stable_typed_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            java = Path(tmp) / "src/main/java"
            resources = Path(tmp) / "src/main/resources"
            java.mkdir(parents=True)
            resources.mkdir(parents=True)
            malformed = resources / "applicationContext.xml"
            malformed.write_text("<beans><bean>", encoding="utf-8")

            batch = framework_adapter_module.run_spring_adapter([
                {"root": str(java), "owner_type": "business"}
            ])

        self.assertIsInstance(batch, CollectorBatch)
        self.assertIn(
            "SPRING_XML_PARSE_FAILED",
            {failure.reason_code for failure in batch.failures},
        )
        self.assertTrue(any(failure.artifact == str(malformed) for failure in batch.failures))

    def test_critical_source_scanners_record_stable_read_diagnostics(self):
        scanners = (
            (
                framework_adapter_module._spring_boot_business_activation,
                "spring_boot_activation_source",
            ),
            (
                framework_adapter_module._spring_data_business_repositories,
                "spring_data_repository_source",
            ),
            (
                framework_adapter_module._spring_data_custom_repository_configuration,
                "spring_data_custom_config_source",
            ),
            (
                framework_adapter_module._spring_transaction_custom_mode,
                "spring_transaction_mode_source",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            java = Path(tmp) / "src/main/java/com/acme"
            java.mkdir(parents=True)
            unreadable = java / "Unreadable.java"
            unreadable.write_text("package com.acme; class Unreadable {}", encoding="utf-8")
            original_read_text = Path.read_text

            def fail_selected_read(path, *args, **kwargs):
                if path.resolve() == unreadable.resolve():
                    raise PermissionError("synthetic unreadable source")
                return original_read_text(path, *args, **kwargs)

            for scanner, marker in scanners:
                with self.subTest(scanner=scanner.__name__), patch.object(
                    Path, "read_text", autospec=True, side_effect=fail_selected_read
                ):
                    evidence, errors = scanner([{
                        "root": str(Path(tmp) / "src/main/java"),
                        "owner_type": "business",
                    }])

                self.assertEqual(evidence, [])
                self.assertEqual(
                    errors,
                    [f"{unreadable.resolve()}:{marker}:PermissionError"],
                )

    def test_unreadable_activation_and_custom_configuration_fail_closed(self):
        activation_error = "/src/Application.java:spring_boot_activation_source:PermissionError"
        repository_error = "/src/OwnerRepository.java:spring_data_repository_source:PermissionError"
        custom_error = "/src/JpaConfig.java:spring_data_custom_config_source:PermissionError"
        transaction_error = "/src/TxConfig.java:spring_transaction_mode_source:PermissionError"
        activation = [{
            "file": "/src/Application.java",
            "business_entry": "com.acme.Application.main",
        }]
        repository = {
            "owner": "com.acme.OwnerRepository",
            "file": "/src/OwnerRepository.java",
            "contracts": ["org.springframework.data.jpa.repository.JpaRepository"],
            "declared_method_counts": {},
        }
        transactional = {
            "owner": "com.acme.BookingService",
            "member": "book",
            "parameter_count": 1,
            "file": "/src/BookingService.java",
            "line": 12,
            "annotation_scope": "method",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime.jar"
            with zipfile.ZipFile(runtime, "w") as archive:
                archive.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=com.acme.Listener\n",
                )
            spring_data = root / "spring-data-jpa-1.jar"
            spring_tx = root / "spring-tx-1.jar"
            spring_aop = root / "spring-aop-1.jar"
            business = root / "business.jar"
            for artifact in (spring_data, spring_tx, spring_aop, business):
                artifact.write_bytes(b"fixture")

            with patch.object(
                framework_adapter_module,
                "_spring_boot_business_activation",
                return_value=([], [activation_error]),
            ):
                runtime_batch = framework_adapter_module.run_runtime_spring_registration_adapter(
                    [], artifact_catalog={"entries": [{
                        "coord": "com.acme:runtime", "jar_path": str(runtime),
                        "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
                    }]}
                )

            with patch.object(
                framework_adapter_module,
                "_spring_data_business_repositories",
                return_value=([repository], [repository_error]),
            ), patch.object(
                framework_adapter_module,
                "_spring_data_custom_repository_configuration",
                return_value=([], [custom_error]),
            ), patch.object(
                framework_adapter_module,
                "_spring_boot_business_activation",
                return_value=(activation, []),
            ):
                spring_data_batch = framework_adapter_module.run_spring_data_repository_adapter(
                    [], artifact_catalog={"entries": [{
                        "coord": "org.springframework.data:spring-data-jpa",
                        "jar_path": str(spring_data),
                    }]}
                )

            with patch.object(
                framework_adapter_module,
                "_spring_transactional_business_methods",
                return_value=([transactional], []),
            ), patch.object(
                framework_adapter_module,
                "_spring_boot_business_activation",
                return_value=(activation, []),
            ), patch.object(
                framework_adapter_module,
                "_spring_transaction_custom_mode",
                return_value=([], [transaction_error]),
            ), patch.object(
                framework_adapter_module,
                "_packaged_transactional_methods",
                return_value=({
                    ("com.acme.BookingService", "book", 1): {
                        "descriptor": "(Ljava/lang/String;)V",
                        "annotation_scope": "method",
                    }
                }, []),
            ):
                transaction_batch = framework_adapter_module.run_spring_transaction_proxy_adapter(
                    [], artifact_catalog={"entries": [
                        {"coord": "__business__", "jar_path": str(business)},
                        {"coord": "org.springframework:spring-tx", "jar_path": str(spring_tx)},
                        {"coord": "org.springframework:spring-aop", "jar_path": str(spring_aop)},
                    ]}
                )

        runtime_edge = next(
            edge for edge in runtime_batch.edges
            if edge.edge_kind == "spring_runtime_registered_callback"
        )
        self.assertEqual(runtime_edge.confidence, "medium")
        self.assertEqual(dict(runtime_edge.metadata)["runtime_activation"], "unproven")
        self.assertTrue(runtime_batch.coverage[0].applicable)
        self.assertEqual(runtime_batch.coverage[0].status, "partial")
        self.assertEqual(
            {failure.reason_code for failure in runtime_batch.failures},
            {"SPRING_BOOT_ACTIVATION_SOURCE_READ_FAILED"},
        )

        self.assertEqual(spring_data_batch.edges, ())
        self.assertTrue(spring_data_batch.coverage[0].applicable)
        self.assertEqual(spring_data_batch.coverage[0].status, "partial")
        self.assertEqual(
            {failure.reason_code for failure in spring_data_batch.failures},
            {
                "SPRING_DATA_REPOSITORY_SOURCE_READ_FAILED",
                "SPRING_DATA_CUSTOM_CONFIG_SOURCE_READ_FAILED",
            },
        )

        self.assertEqual(transaction_batch.edges, ())
        self.assertTrue(transaction_batch.coverage[0].applicable)
        self.assertEqual(transaction_batch.coverage[0].status, "partial")
        self.assertEqual(
            {failure.reason_code for failure in transaction_batch.failures},
            {"SPRING_TRANSACTION_MODE_SOURCE_READ_FAILED"},
        )

    @patch("framework_adapters._mybatis_mapper_contracts")
    def test_mybatis_proxy_adapter_skips_source_scan_without_packaged_runtime(
        self, mapper_contracts
    ):
        adapter = run_mybatis_proxy_adapter([], artifact_catalog={"entries": []})

        self.assertEqual(adapter["status"], "not_applicable")
        self.assertEqual(adapter["edges"], [])
        mapper_contracts.assert_not_called()

    def _mybatis_runtime_catalog(self, module):
        source_root = module / "mybatis-runtime"
        classes = module / "mybatis-runtime-classes"
        sources = {
            "org/apache/ibatis/session/SqlSession.java": (
                "package org.apache.ibatis.session; public interface SqlSession { "
                "Object selectOne(String statement, Object parameter); }"
            ),
            "org/apache/ibatis/binding/MapperMethod.java": (
                "package org.apache.ibatis.binding; import org.apache.ibatis.session.SqlSession; "
                "public class MapperMethod { public Object execute(SqlSession session, Object[] args) { "
                "return session.selectOne(\"statement\", args[0]); } }"
            ),
            "org/apache/ibatis/binding/MapperProxy.java": (
                "package org.apache.ibatis.binding; import java.lang.reflect.Method; "
                "import org.apache.ibatis.session.SqlSession; public class MapperProxy { "
                "public interface MapperMethodInvoker { Object invoke(Object proxy, Method method, "
                "Object[] args, SqlSession session); } public Object invoke(Object proxy, Method method, "
                "Object[] args) { return ((MapperMethodInvoker) null).invoke(proxy, method, args, null); } "
                "public static class PlainMethodInvoker implements MapperMethodInvoker { "
                "private final MapperMethod mapperMethod = new MapperMethod(); "
                "public Object invoke(Object proxy, Method method, Object[] args, SqlSession session) { "
                "return mapperMethod.execute(session, args); } } }"
            ),
        }
        for relative, content in sources.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        classes.mkdir(exist_ok=True)
        subprocess.run(
            ["javac", "-d", str(classes)]
            + [str(source_root / relative) for relative in sorted(sources)],
            check=True,
            capture_output=True,
            text=True,
        )
        jar_path = module / "mybatis-runtime.jar"
        with zipfile.ZipFile(jar_path, "w") as jar:
            for class_file in classes.rglob("*.class"):
                jar.write(class_file, class_file.relative_to(classes).as_posix())
        artifact = module / "application.jar"
        mapper_source = (module / "src/main/java/com/acme/CityMapper.java").read_text(
            encoding="utf-8", errors="replace"
        ) if (module / "src/main/java/com/acme/CityMapper.java").is_file() else ""
        application_source = (module / "src/main/java/com/acme/Application.java").read_text(
            encoding="utf-8", errors="replace"
        ) if (module / "src/main/java/com/acme/Application.java").is_file() else ""
        mapper_bytes = mapper_source.encode("utf-8")
        if "org.apache.ibatis.annotations.Mapper" in mapper_source:
            mapper_bytes += b"Lorg/apache/ibatis/annotations/Mapper;"
        for annotation in ("Select", "Insert", "Update", "Delete"):
            if f"org.apache.ibatis.annotations.{annotation}" in mapper_source:
                mapper_bytes += f"Lorg/apache/ibatis/annotations/{annotation};".encode("ascii")
        application_bytes = application_source.encode("utf-8")
        if "SpringBootApplication" in application_source:
            application_bytes += b"Lorg/springframework/boot/autoconfigure/SpringBootApplication;"
        if "SpringApplication.run" in application_source:
            application_bytes += b"org/springframework/boot/SpringApplication run"
        with zipfile.ZipFile(artifact, "w") as outer:
            outer.writestr("BOOT-INF/classes/com/acme/CityMapper.class", mapper_bytes)
            outer.writestr("BOOT-INF/classes/com/acme/Application.class", application_bytes)
            outer.writestr("BOOT-INF/lib/mybatis-test.jar", jar_path.read_bytes())
            resources = module / "src/main/resources"
            if resources.is_dir():
                for resource in resources.rglob("*.xml"):
                    outer.write(resource, "BOOT-INF/classes/" + resource.relative_to(resources).as_posix())
        return {
            "final_artifact_path": str(artifact),
            "final_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "entries": [{
                "coord": "runtime:mybatis-test",
                "version": "test",
                "jar_path": str(jar_path),
                "artifact_entry": "BOOT-INF/lib/mybatis-test.jar",
                "sha256": hashlib.sha256(jar_path.read_bytes()).hexdigest(),
                "evidence_source": "current_final_artifact",
            }]
        }

    def test_mybatis_proxy_adapter_requires_registration_and_packaged_dispatch_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; @org.springframework.boot.autoconfigure.SpringBootApplication "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            mapper = java / "CityMapper.java"
            mapper_source = (
                "package com.acme; @org.apache.ibatis.annotations.Mapper public interface CityMapper { "
                "@org.apache.ibatis.annotations.Select(\"select 1\") Object find(String state); }"
            )
            mapper.write_text(
                mapper_source,
                encoding="utf-8",
            )
            catalog = self._mybatis_runtime_catalog(module)

            adapter = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=catalog,
                fact_store=Step5ArtifactFactStore.from_catalog(catalog),
            )
            verified_final_sha256 = catalog["final_artifact_sha256"]
            corrupt_sha_catalog = {
                **catalog,
                "entries": [{**catalog["entries"][0], "sha256": "c" * 64}],
            }
            corrupt_sha = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=corrupt_sha_catalog,
            )
            mapper.write_text(
                mapper.read_text(encoding="utf-8").replace(
                    "@org.apache.ibatis.annotations.Mapper ", ""
                ),
                encoding="utf-8",
            )
            unregistered_catalog = self._mybatis_runtime_catalog(module)
            unregistered = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=unregistered_catalog,
            )
            mapper.write_text(mapper_source, encoding="utf-8")
            catalog = self._mybatis_runtime_catalog(module)
            fallback_catalog = {
                "entries": [{
                    **catalog["entries"][0],
                    "evidence_source": "local_maven_fallback",
                }]
            }
            fallback = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=fallback_catalog,
            )

        self.assertEqual(adapter["status"], "complete")
        self.assertEqual(
            {edge["target"] for edge in adapter["edges"]},
            {
                "org.apache.ibatis.binding.MapperProxy.invoke(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])",
                "org.apache.ibatis.binding.MapperMethod.execute(org.apache.ibatis.session.SqlSession,java.lang.Object[])",
                "org.apache.ibatis.session.SqlSession.selectOne(java.lang.String,java.lang.Object)",
            },
        )
        self.assertTrue(all(
            edge["source_owner"] == "com.acme.CityMapper"
            and edge["source_member"] == "find"
            and edge["parameter_count"] == 1
            and edge["provenance"]["authority"] == "final_artifact_javap"
            and edge["provenance"]["mapper_registration"]["artifact_sha256"]
            == verified_final_sha256
            and edge["provenance"]["binding_evidence"]["artifact_sha256"]
            == verified_final_sha256
            and edge["provenance"]["physical_target_evidence"]["target"]
            == edge["target"]
            for edge in adapter["edges"]
        ))
        self.assertEqual(corrupt_sha["edges"], [])
        self.assertTrue(any(
            "artifact_fact_store_identity_failed" in error
            for error in corrupt_sha["errors"]
        ))
        self.assertEqual(unregistered["edges"], [])
        self.assertTrue(any(
            finding["reason_code"] == "mybatis_mapper_registration_unproven"
            for finding in unregistered["findings"]
        ))
        self.assertEqual(fallback["edges"], [])
        self.assertTrue(any(
            finding["reason_code"] == "mybatis_runtime_implementation_unresolved"
            for finding in fallback["findings"]
        ))

    def test_mybatis_final_artifact_replacement_is_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "application.jar"
            replacement = Path(tmp) / "replacement.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/com/acme/App.class", b"original")
            catalog = {
                "final_artifact_path": str(artifact),
                "final_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "entries": [],
            }
            store = Step5ArtifactFactStore.from_catalog(catalog)
            store.inventory("__final_artifact__")
            with zipfile.ZipFile(replacement, "w") as archive:
                archive.writestr("BOOT-INF/classes/com/acme/App.class", b"replacement")
            replacement.replace(artifact)

            packaged, unregistered, activation, errors = (
                framework_adapter_module._packaged_mybatis_contracts(
                    [], catalog, fact_store=store,
                )
            )

        self.assertEqual(([], [], []), (packaged, unregistered, activation))
        self.assertEqual(1, len(errors))
        self.assertIn("artifact_fact_store_identity_failed", errors[0])

    def test_mybatis_packaged_contract_rejects_duplicate_mapper_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "application.jar"
            mapper_bytes = (
                b"Lorg/apache/ibatis/annotations/Mapper;"
                b"Lorg/apache/ibatis/annotations/Select;find"
            )
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/com/acme/CityMapper.class", mapper_bytes,
                )
                archive.writestr(
                    "WEB-INF/classes/com/acme/CityMapper.class", mapper_bytes,
                )
            catalog = {
                "final_artifact_path": str(artifact),
                "final_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "entries": [],
            }
            candidate = {
                "owner": "com.acme.CityMapper", "member": "find",
                "command": "select", "file": "CityMapper.java",
            }

            packaged, unregistered, _activation, errors = (
                framework_adapter_module._packaged_mybatis_contracts(
                    [candidate], catalog,
                )
            )

        self.assertFalse(packaged)
        self.assertEqual("registration", unregistered[0]["_unproven_reason"])
        self.assertTrue(any("mybatis_mapper_class_ambiguous" in item for item in errors))
        failure = framework_adapter_module._framework_failure("mybatis", errors[0])
        self.assertEqual("MYBATIS_MAPPER_CLASS_AMBIGUOUS", failure.reason_code)
        self.assertTrue(failure.blocking)

    def test_mybatis_packaged_contract_rejects_duplicate_xml_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "application.jar"
            mapper_bytes = b"Lorg/apache/ibatis/annotations/Mapper;find"
            mapping = (
                b'<mapper namespace="com.acme.CityMapper">'
                b'<select id="find">select 1</select></mapper>'
            )
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "BOOT-INF/classes/com/acme/CityMapper.class", mapper_bytes,
                )
                archive.writestr("BOOT-INF/classes/mapper/one.xml", mapping)
                archive.writestr("WEB-INF/classes/mapper/two.xml", mapping)
            catalog = {
                "final_artifact_path": str(artifact),
                "final_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "entries": [],
            }
            candidate = {
                "owner": "com.acme.CityMapper", "member": "find",
                "command": "select", "file": "CityMapper.java",
            }

            packaged, unregistered, _activation, errors = (
                framework_adapter_module._packaged_mybatis_contracts(
                    [candidate], catalog,
                )
            )

        self.assertFalse(packaged)
        self.assertEqual("binding", unregistered[0]["_unproven_reason"])
        self.assertTrue(any("mybatis_xml_binding_ambiguous" in item for item in errors))
        failure = framework_adapter_module._framework_failure("mybatis", errors[0])
        self.assertEqual("MYBATIS_XML_BINDING_AMBIGUOUS", failure.reason_code)
        self.assertTrue(failure.blocking)

    def test_mybatis_packaged_contract_creates_fact_store_when_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/com/acme/App.class", b"fixture")
            catalog = {
                "final_artifact_path": str(artifact),
                "final_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "entries": [],
            }

            with patch.object(
                framework_adapter_module, "_verified_final_artifact",
                side_effect=AssertionError("legacy path used"),
            ):
                result = framework_adapter_module._packaged_mybatis_contracts(
                    [], catalog,
                )

        self.assertEqual(([], [], [], []), result)

    def test_mybatis_packaged_contract_streams_large_class_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "application.jar"
            with zipfile.ZipFile(
                artifact, "w", compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                for index in range(24):
                    archive.writestr(
                        f"BOOT-INF/classes/com/acme/Filler{index}.class",
                        b"x" * (1024 * 1024),
                    )
            catalog = {
                "final_artifact_path": str(artifact),
                "final_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "entries": [],
            }

            tracemalloc.start()
            result = framework_adapter_module._packaged_mybatis_contracts([], catalog)
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        self.assertEqual(([], [], [], []), result)
        self.assertLess(peak, 12 * 1024 * 1024)

    def test_artifact_javap_nonzero_exit_is_blocking_parser_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "runtime.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("com/acme/Target.class", b"fixture")
            entry = {
                "coord": "g:a", "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})
            completed = SimpleNamespace(returncode=1, stdout="")
            with patch.object(
                framework_adapter_module.subprocess, "run", return_value=completed,
            ):
                result, error = framework_adapter_module._artifact_javap(
                    entry, "com.acme.Target", ("-p", "-s"), "test", store,
                )

        self.assertIsNone(result)
        self.assertIn("framework_javap_failed", error)
        failure = framework_adapter_module._framework_failure("test", error)
        self.assertEqual("FRAMEWORK_JAVAP_FAILED", failure.reason_code)
        self.assertTrue(failure.blocking)

    def test_artifact_javap_missing_class_is_parser_failure_not_identity_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            jar = Path(tmp) / "runtime.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("com/acme/Present.class", b"fixture")
            entry = {
                "coord": "g:a", "jar_path": str(jar),
                "sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
            }
            store = Step5ArtifactFactStore.from_catalog({"entries": [entry]})

            result, error = framework_adapter_module._artifact_javap(
                entry, "com.acme.Missing", ("-p", "-s"), "test", store,
            )

        self.assertIsNone(result)
        self.assertIn("framework_javap_failed", error)
        self.assertNotIn("artifact_fact_store_identity_failed", error)

    def test_mybatis_mapper_scan_is_partial_instead_of_not_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; "
                "@org.springframework.boot.autoconfigure.SpringBootApplication "
                "@org.mybatis.spring.annotation.MapperScan(\"com.acme.dao\") "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            dao = java / "dao/CityDao.java"
            dao.parent.mkdir(parents=True)
            dao.write_text(
                "package com.acme.dao; public interface CityDao { "
                "@org.apache.ibatis.annotations.Select(\"select 1\") "
                "Object find(String state); }",
                encoding="utf-8",
            )
            catalog = self._mybatis_runtime_catalog(module)

            adapter = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=catalog,
            )
            missing_runtime = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog={"entries": []},
            )

        self.assertEqual(adapter["status"], "partial")
        self.assertTrue(any(
            finding["reason_code"] == "mybatis_mapper_scan_unresolved"
            for finding in adapter["findings"]
        ))
        self.assertEqual(missing_runtime["status"], "partial")
        self.assertTrue(any(
            finding["reason_code"] == "mybatis_mapper_scan_unresolved"
            for finding in missing_runtime["findings"]
        ))

    def test_mybatis_source_mapper_and_xml_must_exist_in_final_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            resources = module / "src/main/resources/mappers"
            java.mkdir(parents=True)
            resources.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; @org.springframework.boot.autoconfigure.SpringBootApplication "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            (java / "CityMapper.java").write_text(
                "package com.acme; @org.apache.ibatis.annotations.Mapper public interface CityMapper { "
                "Object find(String state); }",
                encoding="utf-8",
            )
            (resources / "CityMapper.xml").write_text(
                '<mapper namespace="com.acme.CityMapper"><select id="find">select 1</select></mapper>',
                encoding="utf-8",
            )
            catalog = self._mybatis_runtime_catalog(module)
            artifact = Path(catalog["final_artifact_path"])
            with zipfile.ZipFile(artifact) as archive:
                original = {
                    item.filename: archive.read(item)
                    for item in archive.infolist() if not item.is_dir()
                }

            mutations = {
                "mapper_absent": (
                    "BOOT-INF/classes/com/acme/CityMapper.class",
                    "mybatis_mapper_registration_unproven",
                ),
                "xml_absent": (
                    "BOOT-INF/classes/mappers/CityMapper.xml",
                    "mybatis_mapper_binding_unproven",
                ),
            }
            for name, (removed_entry, reason_code) in mutations.items():
                with self.subTest(mutation=name):
                    with zipfile.ZipFile(artifact, "w") as archive:
                        for entry, content in original.items():
                            if entry != removed_entry:
                                archive.writestr(entry, content)
                    catalog["final_artifact_sha256"] = hashlib.sha256(
                        artifact.read_bytes()
                    ).hexdigest()

                    adapter = run_mybatis_proxy_adapter(
                        [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                        artifact_catalog=catalog,
                    )

                    self.assertEqual(adapter["edges"], [])
                    self.assertTrue(any(
                        finding["reason_code"] == reason_code
                        for finding in adapter["findings"]
                    ))

    def test_mybatis_proxy_adapter_rejects_source_registration_missing_from_final_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; @org.springframework.boot.autoconfigure.SpringBootApplication "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            (java / "CityMapper.java").write_text(
                "package com.acme; @org.apache.ibatis.annotations.Mapper public interface CityMapper { "
                "@org.apache.ibatis.annotations.Select(\"select 1\") Object find(String state); }",
                encoding="utf-8",
            )
            catalog = self._mybatis_runtime_catalog(module)
            artifact = module / "application.jar"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("BOOT-INF/classes/com/acme/Application.class", b"no activation")
            catalog.update({
                "final_artifact_path": str(artifact),
                "final_artifact_sha256": "b" * 64,
            })

            adapter = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=catalog,
            )

        self.assertEqual(adapter["edges"], [])
        self.assertTrue(any(
            finding["reason_code"] == "mybatis_mapper_registration_unproven"
            for finding in adapter["findings"]
        ))

    def test_mybatis_proxy_adapter_reads_mapper_from_packaged_internal_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; @org.springframework.boot.autoconfigure.SpringBootApplication "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            (java / "CityMapper.java").write_text(
                "package com.acme; @org.apache.ibatis.annotations.Mapper public interface CityMapper { "
                "@org.apache.ibatis.annotations.Select(\"select 1\") Object find(String state); }",
                encoding="utf-8",
            )
            catalog = self._mybatis_runtime_catalog(module)
            artifact = Path(catalog["final_artifact_path"])
            with zipfile.ZipFile(artifact) as outer:
                entries = {
                    item.filename: outer.read(item)
                    for item in outer.infolist()
                    if not item.is_dir()
                }
            mapper_entry = "BOOT-INF/classes/com/acme/CityMapper.class"
            internal_jar = module / "library.jar"
            with zipfile.ZipFile(internal_jar, "w") as nested:
                nested.writestr("com/acme/CityMapper.class", entries.pop(mapper_entry))
            with zipfile.ZipFile(artifact, "w") as outer:
                for name, content in entries.items():
                    outer.writestr(name, content)
                outer.writestr("BOOT-INF/lib/library.jar", internal_jar.read_bytes())
            catalog["final_artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            catalog["entries"].append({
                "coord": "com.acme:library",
                "version": "1.0.0",
                "jar_path": str(internal_jar),
                "artifact_entry": "BOOT-INF/lib/library.jar",
                "sha256": hashlib.sha256(internal_jar.read_bytes()).hexdigest(),
                "evidence_source": "current_final_artifact",
                "application_owned": True,
            })

            adapter = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=catalog,
            )

        self.assertEqual(len(adapter["edges"]), 3)
        self.assertTrue(all(
            "BOOT-INF/lib/library.jar!/com/acme/CityMapper.class"
            in edge["provenance"]["file"]
            for edge in adapter["edges"]
        ))

    def test_mybatis_proxy_dispatch_links_final_artifact_business_caller_to_runtime_targets(self):
        caller = SimpleNamespace(
            caller_symbol_id="app-run",
            caller_qualified_key="com.acme.Application.run()",
            callee_key="com.acme.CityMapper.find(java.lang.String)",
            callee_simple_key="find(String)",
            evidence_type="bytecode_invokeinterface",
            evidence_source="current_final_artifact",
            confidence="high",
            file="business.jar!/com/acme/Application.class",
            line=21,
            content="invokeinterface CityMapper.find",
            owner_type="business",
            owner_coord="BUSINESS",
            module="app",
            is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={"com.acme.CityMapper.find(java.lang.String)": [caller]},
        )
        target = (
            "org.apache.ibatis.binding.MapperProxy.invoke"
            "(java.lang.Object,java.lang.reflect.Method,java.lang.Object[])"
        )
        payload = {"adapters": [{
            "adapter": "mybatis_mapper_proxy",
            "version": "1",
            "edges": [{
                "source": "com.acme.CityMapper.find",
                "source_owner": "com.acme.CityMapper",
                "source_member": "find",
                "parameter_count": 1,
                "target": target,
                "edge_kind": "mybatis_mapper_proxy_dispatch",
                "confidence": "high",
                "conditions": [],
                "ambiguity": False,
                "provenance": {
                    "authority": "final_artifact_javap",
                    "artifact_sha256": "a" * 64,
                },
            }],
        }]}

        stats = ingest_framework_payload(graph, payload)

        self.assertEqual(stats["framework_mybatis_proxy_dispatch_edges"], 1)
        self.assertEqual(len(graph.reverse_edges[target]), 1)
        self.assertEqual(graph.reverse_edges[target][0].caller_symbol_id, "app-run")
        self.assertEqual(
            graph.reverse_edges[target][0].evidence_type,
            "mybatis_mapper_proxy_dispatch",
        )
        self.assertEqual(
            graph.reverse_edges[target][0].evidence_source,
            "framework_semantic",
        )
        self.assertEqual(
            graph.reverse_edges[target][0].caller_evidence_source,
            "current_final_artifact",
        )

        source_only = SimpleNamespace(**{
            **vars(caller),
            "evidence_type": "source_ast",
            "evidence_source": "source",
        })
        source_graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={"com.acme.CityMapper.find(java.lang.String)": [source_only]},
        )
        source_stats = ingest_framework_payload(source_graph, payload)
        self.assertNotIn(target, source_graph.reverse_edges)
        self.assertEqual(source_stats["framework_mybatis_proxy_dispatch_edges"], 0)

    def test_mybatis_proxy_adapter_accepts_only_known_external_dtd(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            resources = module / "src/main/resources/mappers"
            java.mkdir(parents=True)
            resources.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; @org.springframework.boot.autoconfigure.SpringBootApplication "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            (java / "CityMapper.java").write_text(
                "package com.acme; @org.apache.ibatis.annotations.Mapper public interface CityMapper { "
                "Object find(String state); }",
                encoding="utf-8",
            )
            mapper_xml = resources / "CityMapper.xml"
            mapper_xml.write_text(
                '<?xml version="1.0"?><!DOCTYPE mapper PUBLIC '
                '"-//mybatis.org//DTD Mapper 3.0//EN" '
                '"http://mybatis.org/dtd/mybatis-3-mapper.dtd">'
                '<mapper namespace="com.acme.CityMapper">'
                '<select id="find">select 1</select></mapper>',
                encoding="utf-8",
            )
            catalog = self._mybatis_runtime_catalog(module)

            known = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=catalog,
            )
            mapper_xml.write_text(
                mapper_xml.read_text(encoding="utf-8").replace(
                    "mybatis.org/dtd/mybatis-3-mapper.dtd",
                    "example.invalid/unknown.dtd",
                ),
                encoding="utf-8",
            )
            unknown = run_mybatis_proxy_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=catalog,
            )

        self.assertEqual(len(known["edges"]), 3)
        self.assertEqual(unknown["edges"], [])
        self.assertTrue(any("mybatis_xml:ParseError" in item for item in unknown["errors"]))

    def test_spring_transaction_adapter_requires_packaged_business_annotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; @org.springframework.boot.autoconfigure.SpringBootApplication "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            (java / "BookingService.java").write_text(
                "package com.acme; import org.springframework.transaction.annotation.Transactional; "
                "class BookingService { @Transactional public void book(String... names) {} }",
                encoding="utf-8",
            )

            payload = run_framework_adapters(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog={"entries": []},
            )

        adapter = next(
            item for item in payload["adapters"]
            if item["adapter"] == "spring_transaction_proxy"
        )
        self.assertEqual(adapter["status"], "partial")
        self.assertEqual(adapter["edges"], [])
        self.assertTrue(any(
            finding["reason_code"] == "spring_transaction_business_annotation_unverified"
            for finding in adapter["findings"]
        ))

    def test_spring_transaction_adapter_uses_packaged_aop_implementation_methods(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            framework = module / "framework"
            classes = module / "classes"
            business_classes = module / "business-classes"
            java.mkdir(parents=True)
            classes.mkdir()
            business_classes.mkdir()
            sources = {
                "org/aopalliance/intercept/MethodInvocation.java": (
                    "package org.aopalliance.intercept; public interface MethodInvocation {}"
                ),
                "org/springframework/transaction/interceptor/TransactionInterceptor.java": (
                    "package org.springframework.transaction.interceptor; "
                    "public class TransactionInterceptor { public Object invoke("
                    "org.aopalliance.intercept.MethodInvocation invocation) { return null; } }"
                ),
                "org/springframework/transaction/interceptor/TransactionAspectSupport.java": (
                    "package org.springframework.transaction.interceptor; "
                    "public abstract class TransactionAspectSupport { public interface InvocationCallback {} "
                    "protected Object invokeWithinTransaction(java.lang.reflect.Method method, "
                    "Class<?> owner, InvocationCallback callback) { return null; } }"
                ),
                "org/springframework/aop/framework/ReflectiveMethodInvocation.java": (
                    "package org.springframework.aop.framework; public class "
                    "ReflectiveMethodInvocation { public Object proceed() { return null; } }"
                ),
                "org/springframework/transaction/annotation/Transactional.java": (
                    "package org.springframework.transaction.annotation; "
                    "@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME) "
                    "@java.lang.annotation.Target({java.lang.annotation.ElementType.TYPE, "
                    "java.lang.annotation.ElementType.METHOD}) public @interface Transactional {}"
                ),
            }
            source_paths = []
            for relative, content in sources.items():
                path = framework / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                source_paths.append(str(path))
            subprocess.run(
                ["javac", "-d", str(classes), *source_paths],
                check=True, capture_output=True, text=True,
            )
            (java / "Application.java").write_text(
                "package com.acme; @org.springframework.boot.autoconfigure.SpringBootApplication "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            (java / "BookingService.java").write_text(
                "package com.acme; class BookingService { "
                "@org.springframework.transaction.annotation.Transactional "
                "public void book(String... names) {} public void read() {} }",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "javac", "-cp", str(classes), "-d", str(business_classes),
                    str(java / "BookingService.java"),
                ],
                check=True, capture_output=True, text=True,
            )
            tx_jar = module / "spring-tx-7.0.8.jar"
            aop_jar = module / "spring-aop-7.0.8.jar"
            business_jar = module / "business-classes.jar"
            with zipfile.ZipFile(tx_jar, "w") as jar:
                for class_file in classes.rglob("*.class"):
                    relative = class_file.relative_to(classes).as_posix()
                    if relative.startswith(("org/springframework/transaction/", "org/aopalliance/")):
                        jar.write(class_file, relative)
            with zipfile.ZipFile(aop_jar, "w") as jar:
                for class_file in classes.rglob("org/springframework/aop/**/*.class"):
                    jar.write(class_file, class_file.relative_to(classes).as_posix())
            with zipfile.ZipFile(business_jar, "w") as jar:
                for class_file in business_classes.rglob("*.class"):
                    jar.write(class_file, class_file.relative_to(business_classes).as_posix())
                jar.writestr("com/acme/Application.class", b"packaged-application")
            business_sha = hashlib.sha256(business_jar.read_bytes()).hexdigest()
            tx_sha = hashlib.sha256(tx_jar.read_bytes()).hexdigest()
            aop_sha = hashlib.sha256(aop_jar.read_bytes()).hexdigest()

            payload = run_framework_adapters(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog={"entries": [
                    {
                        "coord": "org.springframework:spring-tx", "jar_path": str(tx_jar),
                        "artifact_entry": "BOOT-INF/lib/spring-tx-7.0.8.jar", "sha256": tx_sha,
                    },
                    {
                        "coord": "runtime:spring-aop-7.0.8", "jar_path": str(aop_jar),
                        "artifact_entry": "BOOT-INF/lib/spring-aop-7.0.8.jar", "sha256": aop_sha,
                    },
                    {
                        "coord": "__business__", "jar_path": str(business_jar),
                        "artifact_entry": "<business-classes>", "sha256": business_sha,
                    },
                ]},
            )

        adapter = next(
            item for item in payload["adapters"]
            if item["adapter"] == "spring_transaction_proxy"
        )
        self.assertEqual(adapter["status"], "complete", adapter)
        self.assertEqual({edge["source"] for edge in adapter["edges"]}, {
            "com.acme.BookingService.book/1",
        })
        self.assertEqual({edge["target"] for edge in adapter["edges"]}, {
            "org.springframework.transaction.interceptor.TransactionInterceptor.invoke(org.aopalliance.intercept.MethodInvocation)",
            "org.springframework.transaction.interceptor.TransactionAspectSupport.invokeWithinTransaction(java.lang.reflect.Method,java.lang.Class,org.springframework.transaction.interceptor.TransactionAspectSupport.InvocationCallback)",
            "org.springframework.aop.framework.ReflectiveMethodInvocation.proceed()",
        })
        self.assertTrue(all(
            edge["provenance"]["authority"] == "final_artifact_javap"
            and edge["provenance"]["business_artifact_sha256"] == business_sha
            and edge["provenance"]["business_activation"]
            for edge in adapter["edges"]
        ))

    def test_spring_transaction_proxy_links_only_callers_of_annotated_method(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        business_jar = Path(temp_dir.name) / "application.jar"
        framework_jar = Path(temp_dir.name) / "spring-tx.jar"
        with zipfile.ZipFile(business_jar, "w") as archive:
            archive.writestr(
                "BOOT-INF/classes/com/acme/Application.class", b"application"
            )
            archive.writestr(
                "BOOT-INF/classes/com/acme/AppRunner.class", b"caller"
            )
        framework_class = (
            "org/springframework/transaction/interceptor/"
            "TransactionInterceptor.class"
        )
        with zipfile.ZipFile(framework_jar, "w") as archive:
            archive.writestr(framework_class, b"transaction-interceptor")
        business_sha = hashlib.sha256(business_jar.read_bytes()).hexdigest()
        framework_sha = hashlib.sha256(framework_jar.read_bytes()).hexdigest()
        caller = SimpleNamespace(
            caller_symbol_id="runner", caller_qualified_key="com.acme.AppRunner.run()",
            callee_key="com.acme.BookingService.book(String[])",
            callee_simple_key="book(String[])", evidence_type="bytecode_method_invocation",
            evidence_source="current_final_artifact", confidence="high",
            file=(
                f"{business_jar}!/BOOT-INF/classes/com/acme/AppRunner.class"
            ), line=12, content="invoke book",
            owner_type="business", owner_coord="BUSINESS", module="app", is_test=False,
            artifact_sha256=business_sha,
            artifact_entry="BOOT-INF/classes/com/acme/AppRunner.class",
        )
        unrelated = SimpleNamespace(
            caller_symbol_id="other", caller_qualified_key="com.acme.Other.run()",
            callee_key="com.acme.BookingService.read()", callee_simple_key="read()",
            evidence_type="bytecode_method_invocation", evidence_source="current_final_artifact",
            confidence="high", file="business.jar!/Other.class", line=4, content="invoke read",
            owner_type="business", owner_coord="BUSINESS", module="app", is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={}, reverse_edges={
                "com.acme.BookingService.book(String[])": [caller],
                "com.acme.BookingService.read()": [unrelated],
            },
        )
        target = (
            "org.springframework.transaction.interceptor.TransactionInterceptor."
            "invoke(org.aopalliance.intercept.MethodInvocation)"
        )
        payload = {"adapters": [{
            "adapter": "spring_transaction_proxy", "version": "1",
            "edges": [{
                "source": "com.acme.BookingService.book/1", "target": target,
                "source_owner": "com.acme.BookingService", "source_member": "book",
                "parameter_count": 1, "edge_kind": "spring_transaction_proxy_dispatch",
                "confidence": "high", "conditions": [], "ambiguity": False,
                "provenance": {
                    "jar": str(framework_jar), "authority": "final_artifact_javap",
                    "artifact_sha256": framework_sha,
                    "class_or_resource_entry": framework_class,
                    "business_artifact_sha256": business_sha,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "artifact_path": str(business_jar),
                        "artifact_entry": "BOOT-INF/classes/com/acme/Application.class",
                        "artifact_sha256": business_sha,
                        "authority": "current_final_artifact_classfile",
                    }],
                },
            }],
        }]}

        stats = ingest_framework_payload(graph, payload)

        self.assertEqual(stats["framework_transaction_proxy_edges"], 1)
        self.assertEqual(len(graph.reverse_edges[target]), 1)
        self.assertEqual(graph.reverse_edges[target][0].caller_symbol_id, "runner")
        self.assertEqual(
            graph.reverse_edges[target][0].evidence_type,
            "spring_transaction_proxy_dispatch",
        )
        self.assertTrue(
            graph.reverse_edges[target][0].framework_final_artifact_verified
        )

    def test_spring_data_repository_adapter_refuses_custom_repository_factory(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; @org.springframework.boot.autoconfigure.SpringBootApplication "
                "@org.springframework.data.jpa.repository.config.EnableJpaRepositories("
                "repositoryFactoryBeanClass = CustomFactory.class) "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            (java / "OwnerRepository.java").write_text(
                "package com.acme; import org.springframework.data.jpa.repository.JpaRepository; "
                "public interface OwnerRepository extends JpaRepository<Owner, Integer> {}",
                encoding="utf-8",
            )

            payload = run_framework_adapters(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog={"entries": []},
            )

        adapter = next(
            item for item in payload["adapters"]
            if item["adapter"] == "spring_data_repository_proxy"
        )
        self.assertEqual(adapter["status"], "partial")
        self.assertEqual(adapter["edges"], [])
        self.assertTrue(any(
            finding["reason_code"] == "spring_data_custom_repository_factory"
            and finding["subject"].endswith("Application.java")
            for finding in adapter["findings"]
        ))

    def test_spring_data_repository_adapter_uses_packaged_implementation_bytecode(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            implementation_source = module / "implementation/org/springframework/data/jpa/repository/support"
            classes = module / "classes"
            java.mkdir(parents=True)
            implementation_source.mkdir(parents=True)
            classes.mkdir()
            (java / "Application.java").write_text(
                "package com.acme; @org.springframework.boot.autoconfigure.SpringBootApplication "
                "class Application { public static void main(String[] args) { "
                "org.springframework.boot.SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            (java / "OwnerRepository.java").write_text(
                "package com.acme; import org.springframework.data.jpa.repository.JpaRepository; "
                "public interface OwnerRepository extends JpaRepository<Owner, Integer> {}",
                encoding="utf-8",
            )
            implementation = implementation_source / "SimpleJpaRepository.java"
            implementation.write_text(
                "package org.springframework.data.jpa.repository.support; "
                "public class SimpleJpaRepository { "
                "public Object save(Object value) { return value; } "
                "public java.util.Optional findById(Object id) { return java.util.Optional.empty(); } }",
                encoding="utf-8",
            )
            subprocess.run(
                ["javac", "-d", str(classes), str(implementation)],
                check=True, capture_output=True, text=True,
            )
            jar_path = module / "spring-data-jpa.jar"
            with zipfile.ZipFile(jar_path, "w") as jar:
                for class_file in classes.rglob("*.class"):
                    jar.write(class_file, class_file.relative_to(classes).as_posix())
            business_jar = module / "application.jar"
            with zipfile.ZipFile(business_jar, "w") as jar:
                jar.writestr("BOOT-INF/classes/com/acme/Application.class", b"application")
            business_sha = hashlib.sha256(business_jar.read_bytes()).hexdigest()
            implementation_sha = hashlib.sha256(jar_path.read_bytes()).hexdigest()

            payload = run_framework_adapters(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog={"entries": [
                    {
                        "coord": "org.springframework.data:spring-data-jpa",
                        "jar_path": str(jar_path),
                        "artifact_entry": "BOOT-INF/lib/spring-data-jpa.jar",
                        "sha256": implementation_sha,
                    },
                    {
                        "coord": "__business__",
                        "jar_path": str(business_jar),
                        "sha256": business_sha,
                    },
                ]},
            )

        adapter = next(
            item for item in payload["adapters"]
            if item["adapter"] == "spring_data_repository_proxy"
        )
        self.assertEqual(adapter["status"], "complete")
        self.assertEqual(
            {edge["target"] for edge in adapter["edges"]},
            {
                "org.springframework.data.jpa.repository.support.SimpleJpaRepository.findById(java.lang.Object)",
                "org.springframework.data.jpa.repository.support.SimpleJpaRepository.save(java.lang.Object)",
            },
        )
        self.assertTrue(all(
            edge["source"] == "com.acme.OwnerRepository"
            and edge["provenance"]["artifact_entry"] == "BOOT-INF/lib/spring-data-jpa.jar"
            and edge["provenance"]["authority"] == "final_artifact_javap"
            for edge in adapter["edges"]
        ))

    def test_spring_data_proxy_dispatch_links_business_repository_call_to_implementation(self):
        caller = SimpleNamespace(
            caller_symbol_id="controller", caller_qualified_key="com.acme.OwnerController.show(Integer)",
            callee_key="com.acme.OwnerRepository.findById(Integer)", callee_simple_key="findById(Integer)",
            evidence_type="bytecode_invokeinterface", confidence="high", file="app.jar", line=19,
            content="invokeinterface OwnerRepository.findById", owner_type="business",
            owner_coord="BUSINESS", module="app", is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={"com.acme.OwnerRepository.findById(Integer)": [caller]},
        )
        payload = {"adapters": [{
            "adapter": "spring_data_repository_proxy", "version": "1",
            "edges": [{
                "source": "com.acme.OwnerRepository",
                "target": "org.springframework.data.jpa.repository.support.SimpleJpaRepository.findById(java.lang.Object)",
                "target_member": "findById", "parameter_count": 1,
                "edge_kind": "spring_data_repository_proxy_dispatch",
                "confidence": "high", "conditions": [], "ambiguity": False,
                "provenance": {"jar": "/runtime/spring-data-jpa.jar", "authority": "final_artifact_javap"},
            }],
        }]}

        stats = ingest_framework_payload(graph, payload)

        linked = graph.reverse_edges[
            "org.springframework.data.jpa.repository.support.SimpleJpaRepository.findById(java.lang.Object)"
        ]
        normalized_linked = graph.reverse_edges[
            "org.springframework.data.jpa.repository.support.SimpleJpaRepository.findById(Object)"
        ]
        self.assertEqual(stats["framework_proxy_dispatch_edges"], 1)
        self.assertEqual(linked[0].caller_symbol_id, "controller")
        self.assertEqual(normalized_linked[0].caller_symbol_id, "controller")
        self.assertEqual(linked[0].evidence_type, "spring_data_repository_proxy_dispatch")
        self.assertEqual(linked[0].callee_key, payload["adapters"][0]["edges"][0]["target"])

    def test_spring_data_proxy_dispatch_refuses_ambiguous_repository_overloads(self):
        def caller(symbol, signature):
            return SimpleNamespace(
                caller_symbol_id=symbol, caller_qualified_key=f"com.acme.Service.{symbol}()",
                callee_key=f"com.acme.OwnerRepository.save({signature})",
                callee_simple_key=f"save({signature})", evidence_type="source_ast",
                confidence="high", file="Service.java", line=1, content="save",
                owner_type="business", owner_coord="BUSINESS", module="app", is_test=False,
            )

        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={
                "com.acme.OwnerRepository.save(Object)": [caller("one", "Object")],
                "com.acme.OwnerRepository.save(String)": [caller("two", "String")],
            },
        )
        target = "org.springframework.data.jpa.repository.support.SimpleJpaRepository.save(java.lang.Object)"
        payload = {"adapters": [{
            "adapter": "spring_data_repository_proxy", "version": "1",
            "edges": [{
                "source": "com.acme.OwnerRepository", "target": target,
                "target_member": "save", "parameter_count": 1,
                "repository_declared_method_count": 2,
                "edge_kind": "spring_data_repository_proxy_dispatch",
                "confidence": "high", "conditions": [], "ambiguity": False,
                "provenance": {"jar": "/runtime/spring-data-jpa.jar"},
            }],
        }]}

        stats = ingest_framework_payload(graph, payload)

        self.assertNotIn(target, graph.reverse_edges)
        self.assertEqual(stats["framework_proxy_dispatch_edges"], 0)
        self.assertEqual(stats["ambiguous_framework_proxy_dispatches"], 1)

    def test_spring_data_proxy_dispatch_deduplicates_equivalent_lookup_aliases(self):
        caller = SimpleNamespace(
            caller_symbol_id="controller", caller_qualified_key="com.acme.Controller.show(Integer)",
            callee_key="com.acme.OwnerRepository.findById(Integer)",
            callee_simple_key="findById(Integer)", evidence_type="source_ast",
            confidence="high", file="Controller.java", line=1, content="findById",
            owner_type="business", owner_coord="BUSINESS", module="app", is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={
                "com.acme.OwnerRepository.findById(Integer)": [caller],
                "com.acme.OwnerRepository.findById(java.lang.Integer)": [caller],
            },
        )
        target = "org.springframework.data.jpa.repository.support.SimpleJpaRepository.findById(java.lang.Object)"
        payload = {"adapters": [{
            "adapter": "spring_data_repository_proxy", "version": "1",
            "edges": [{
                "source": "com.acme.OwnerRepository", "target": target,
                "target_member": "findById", "parameter_count": 1,
                "repository_declared_method_count": 0,
                "edge_kind": "spring_data_repository_proxy_dispatch",
                "confidence": "high", "conditions": [], "ambiguity": False,
                "provenance": {"jar": "/runtime/spring-data-jpa.jar"},
            }],
        }]}

        stats = ingest_framework_payload(graph, payload)

        self.assertEqual(stats["framework_proxy_dispatch_edges"], 1)
        self.assertEqual(stats["ambiguous_framework_proxy_dispatches"], 0)
        self.assertEqual(len(graph.reverse_edges[target]), 1)

    def test_spring_data_proxy_dispatch_prefers_final_artifact_business_edge(self):
        common = {
            "caller_symbol_id": "controller",
            "caller_qualified_key": "com.acme.Controller.save()",
            "callee_simple_key": "save(Object)",
            "confidence": "high", "owner_type": "business",
            "owner_coord": "BUSINESS", "module": "app", "is_test": False,
        }
        source_edge = SimpleNamespace(
            **common, callee_key="com.acme.OwnerRepository.save(Owner)",
            evidence_type="ast_method_invocation", file="Controller.java", line=10,
            content="repository.save(owner)",
        )
        artifact_edge = SimpleNamespace(
            **common, callee_key="com.acme.OwnerRepository.save(java.lang.Object)",
            evidence_type="bytecode_method_invocation", file="business.jar!/Controller.class", line=28,
            content="invokeinterface OwnerRepository.save", evidence_source="current_final_artifact",
        )
        graph = SimpleNamespace(
            methods_by_id={},
            reverse_edges={
                "com.acme.OwnerRepository.save(Owner)": [source_edge],
                "com.acme.OwnerRepository.save(java.lang.Object)": [artifact_edge],
            },
        )
        target = "org.springframework.data.jpa.repository.support.SimpleJpaRepository.save(java.lang.Object)"
        payload = {"adapters": [{
            "adapter": "spring_data_repository_proxy", "version": "1",
            "edges": [{
                "source": "com.acme.OwnerRepository", "target": target,
                "target_member": "save", "parameter_count": 1,
                "repository_declared_method_count": 0,
                "edge_kind": "spring_data_repository_proxy_dispatch",
                "confidence": "high", "conditions": [], "ambiguity": False,
                "provenance": {"jar": "/runtime/spring-data-jpa.jar"},
            }],
        }]}

        ingest_framework_payload(graph, payload)

        linked = graph.reverse_edges[target]
        self.assertEqual(len(linked), 1)
        self.assertEqual(linked[0].evidence_source, "framework_semantic")
        self.assertEqual(linked[0].caller_evidence_source, "current_final_artifact")
        self.assertEqual(linked[0].line, 28)

    def test_spring_xml_property_ref_emits_component_injection_edge(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java"
            resources = module / "src/main/resources"
            java.mkdir(parents=True)
            resources.mkdir(parents=True)
            (resources / "beans.xml").write_text(
                "<beans><bean id=\"service\" class=\"com.acme.Service\">"
                "<property name=\"client\" ref=\"client\"/></bean>"
                "<bean id=\"client\" class=\"com.acme.Client\"/></beans>",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(java)}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(
            edge["edge_kind"] == "spring_xml_property_injection"
            and edge["source"] == "com.acme.Service"
            and edge["target"] == "com.acme.Client"
            for edge in spring["edges"]
        ))

    def test_spring_message_listener_annotations_emit_runtime_active_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Listeners.java").write_text(
                "package com.acme; "
                "class Listeners { "
                "@org.springframework.kafka.annotation.KafkaListener(topics=\"orders\") void kafka(String value) {} "
                "@org.springframework.amqp.rabbit.annotation.RabbitListener(queues=\"orders\") void rabbit(String value) {} "
                "@org.springframework.jms.annotation.JmsListener(destination=\"orders\") void jms(Object value) {} "
                "}",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        active_targets = {
            edge["target"] for edge in spring["edges"]
            if edge["edge_kind"] == "spring_runtime_active_entry"
        }
        self.assertEqual(
            active_targets,
            {"com.acme.Listeners.kafka", "com.acme.Listeners.rabbit", "com.acme.Listeners.jms"},
        )

    def test_dubbo_spi_resource_registration_is_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            dubbo = module / "src/main/resources/META-INF/dubbo"
            java.mkdir(parents=True)
            dubbo.mkdir(parents=True)
            (java / "DemoFilter.java").write_text(
                "package com.acme; class DemoFilter {}", encoding="utf-8"
            )
            (dubbo / "org.apache.dubbo.rpc.Filter").write_text(
                "demo=com.acme.DemoFilter\n", encoding="utf-8"
            )

            payload = run_framework_adapters([{"root": str(module / "src/main/java")}])

        spi = next(item for item in payload["adapters"] if item["adapter"] == "java_spi")
        self.assertTrue(any(
            edge["edge_kind"] == "dubbo_spi_registration"
            and edge["source"] == "org.apache.dubbo.rpc.Filter"
            and edge["target"] == "com.acme.DemoFilter"
            for edge in spi["edges"]
        ))

    def test_dubbo_spi_provider_is_attached_only_to_known_interface_method(self):
        interface_method = SimpleNamespace(
            symbol_id="filter-api", class_fqcn="org.apache.dubbo.rpc.Filter",
            method_name="invoke", qualified_key="org.apache.dubbo.rpc.Filter.invoke(java.lang.Object)",
        )
        provider_method = SimpleNamespace(
            symbol_id="demo-filter", class_fqcn="com.acme.DemoFilter",
            method_name="invoke", qualified_key="com.acme.DemoFilter.invoke(java.lang.Object)",
        )
        unrelated_method = SimpleNamespace(
            symbol_id="unrelated", class_fqcn="com.acme.DemoFilter",
            method_name="helper", qualified_key="com.acme.DemoFilter.helper()",
        )
        graph = SimpleNamespace(
            methods_by_id={
                "filter-api": interface_method,
                "demo-filter": provider_method,
                "unrelated": unrelated_method,
            },
            reverse_edges={},
        )
        payload = {"adapters": [{
            "adapter": "java_spi", "version": "1",
            "edges": [{
                "source": "org.apache.dubbo.rpc.Filter",
                "target": "com.acme.DemoFilter",
                "edge_kind": "dubbo_spi_registration",
                "confidence": "high",
                "conditions": [], "ambiguity": False,
            }],
        }]}

        stats = ingest_framework_payload(graph, payload)

        self.assertEqual(stats["matched_callback_edges"], 1)
        self.assertIn("demo-filter", graph.framework_entry_symbols)
        self.assertNotIn("unrelated", graph.framework_entry_symbols)

    def test_java_text_block_content_does_not_create_framework_edge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Documentation.java").write_text(
                'package com.acme; class Documentation { String sample = """\n'
                '@EventListener public void ghost(Object event) {}\n'
                '"""; }\n',
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertFalse(any("ghost" in str(edge) for edge in spring["edges"]))

    def test_dynamic_proxy_text_inside_string_does_not_create_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Documentation.java").write_text(
                'package com.acme; class Documentation { String sample = '
                '"Proxy.newProxyInstance(loader, new Class[]{Api.class}, handler)"; }\n',
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        proxy = next(item for item in payload["adapters"] if item["adapter"] == "dynamic_proxy_basic")
        self.assertEqual(proxy["status"], "not_applicable")
        self.assertEqual(proxy["edges"], [])

    def test_multiline_mybatis_annotation_is_bound_by_ast(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "DemoMapper.java").write_text(
                "package com.acme; interface DemoMapper {\n"
                "  @org.apache.ibatis.annotations.Select(\n"
                "    {\"select 1\"}\n"
                "  )\n"
                "  int find();\n"
                "}\n",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        mybatis = next(item for item in payload["adapters"] if item["adapter"] == "mybatis")
        self.assertTrue(any(
            edge.get("target") == "com.acme.DemoMapper.find"
            and (edge.get("provenance") or {}).get("parser") == "tree_sitter"
            for edge in mybatis["edges"]
        ))

    def test_commented_spring_annotations_do_not_create_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Disabled.java").write_text(
                "package com.acme; class Disabled { /* @EventListener public void ghost(Object e) {} */ "
                "// @Scheduled(fixedDelay=1) public void task() {}\n"
                "public void live() {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertFalse(any("ghost" in str(edge) or "task" in str(edge) for edge in spring["edges"]))

    def test_spi_spring_and_mybatis_emit_independent_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            resources = module / "src/main/resources"
            java.mkdir(parents=True)
            (resources / "META-INF/services").mkdir(parents=True)
            (resources / "mappers").mkdir(parents=True)
            (java / "Listener.java").write_text(
                "package com.acme; import org.springframework.context.event.EventListener; "
                "class Listener { @EventListener public void handle(Object event) {} }",
                encoding="utf-8",
            )
            (java / "PluginOne.java").write_text(
                "package com.acme; import org.springframework.stereotype.Service; "
                "@Service class PluginOne implements Plugin {}",
                encoding="utf-8",
            )
            (resources / "META-INF/services/com.acme.Plugin").write_text(
                "com.acme.PluginOne\ncom.acme.PluginTwo\n", encoding="utf-8",
            )
            (resources / "mappers/Demo.xml").write_text(
                '<mapper namespace="com.acme.DemoMapper">'
                '<select id="find" resultType="com.acme.Dto">select 1</select></mapper>',
                encoding="utf-8",
            )

            payload = run_framework_adapters([{'root': str(module / 'src/main/java')}])

        adapters = {item['adapter']: item for item in payload['adapters']}
        self.assertEqual(adapters['java_spi']['status'], 'partial')
        self.assertEqual(len(adapters['java_spi']['edges']), 2)
        self.assertEqual(adapters['spring_basic']['edges'][0]['edge_kind'], 'spring_event_listener')
        self.assertTrue(any(edge['edge_kind'] == 'spring_bean_dispatch' for edge in adapters['spring_basic']['edges']))
        self.assertEqual(adapters['mybatis']['edges'][0]['target'], 'com.acme.DemoMapper.find')
        self.assertEqual(adapters['mybatis']['findings'][0]['value'], 'com.acme.Dto')

    def test_absent_framework_is_not_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'src/main/java'
            root.mkdir(parents=True)
            payload = run_framework_adapters([{'root': str(root)}])
        self.assertTrue(all(item['status'] == 'not_applicable' for item in payload['adapters']))

    def test_spring_callback_edges_are_attached_to_matching_graph_methods(self):
        method = SimpleNamespace(symbol_id="m1", qualified_key="com.acme.Listener.handle(java.lang.Object)")
        graph = SimpleNamespace(methods_by_id={"m1": method})
        payload = {"adapters": [{
            "adapter": "spring_basic", "version": "1",
            "edges": [{
                "source": "framework:spring-event-dispatch",
                "target": "com.acme.Listener.handle",
                "edge_kind": "spring_event_listener",
                "confidence": "high",
            }],
        }]}

        stats = ingest_framework_payload(graph, payload)

        self.assertEqual(stats["matched_callback_edges"], 1)
        self.assertEqual(graph.framework_entry_symbols["m1"][0]["adapter"], "spring_basic")

    def test_spring_runner_emits_framework_callback_edge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Startup.java").write_text(
                "package com.acme; import org.springframework.stereotype.Component; "
                "import org.springframework.boot.ApplicationRunner; "
                "@Component class Startup implements ApplicationRunner { public void run(Object args) {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(edge["edge_kind"] == "spring_framework_callback" for edge in spring["edges"]))

    def test_spring_scheduled_method_emits_runtime_active_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "CleanupJob.java").write_text(
                "package com.acme; import org.springframework.scheduling.annotation.Scheduled; "
                "class CleanupJob { @Scheduled(fixedDelay = 1000) public void cleanup() {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(
            edge["edge_kind"] == "spring_runtime_active_entry"
            and edge["target"] == "com.acme.CleanupJob.cleanup"
            for edge in spring["edges"]
        ))

    def test_jpa_lifecycle_method_emits_conditional_framework_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "AuditEntity.java").write_text(
                "package com.acme; import jakarta.persistence.Entity; "
                "import jakarta.persistence.PrePersist; @Entity class AuditEntity { "
                "@PrePersist public void beforeInsert() {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        lifecycle = next(
            edge for edge in spring["edges"]
            if edge["target"] == "com.acme.AuditEntity.beforeInsert"
        )
        self.assertEqual(lifecycle["edge_kind"], "jpa_lifecycle_callback")
        self.assertEqual(lifecycle["runtime_activation"], "conditional")

    def test_async_annotation_alone_does_not_fabricate_runtime_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "AsyncWorker.java").write_text(
                "package com.acme; import org.springframework.scheduling.annotation.Async; "
                "class AsyncWorker { @Async public void work() {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertFalse(any(edge.get("target") == "com.acme.AsyncWorker.work" for edge in spring["edges"]))

    def test_spring_post_construct_method_emits_runtime_active_entry_without_spring_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Warmup.java").write_text(
                "package com.acme; import jakarta.annotation.PostConstruct; "
                "class Warmup { @PostConstruct public void init() {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(
            edge["edge_kind"] == "spring_runtime_active_entry"
            and edge["target"] == "com.acme.Warmup.init"
            for edge in spring["edges"]
        ))

    def test_spring_xml_scheduled_task_emits_runtime_active_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            resources = module / "src/main/resources"
            java.mkdir(parents=True)
            resources.mkdir(parents=True)
            (java / "CleanupJob.java").write_text(
                "package com.acme; class CleanupJob { public void cleanup() {} }",
                encoding="utf-8",
            )
            (resources / "spring-jobs.xml").write_text(
                """<beans xmlns:task="http://www.springframework.org/schema/task">
  <bean id="cleanupJob" class="com.acme.CleanupJob"/>
  <task:scheduled-tasks>
    <task:scheduled ref="cleanupJob" method="cleanup" fixed-delay="1000"/>
  </task:scheduled-tasks>
</beans>""",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(module / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(
            edge["edge_kind"] == "spring_runtime_active_entry"
            and edge["target"] == "com.acme.CleanupJob.cleanup"
            and edge["evidence"].get("xml_kind") == "spring_xml_scheduled_task"
            for edge in spring["edges"]
        ))

    def test_spring_xml_quartz_method_invoking_job_emits_runtime_active_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            resources = module / "src/main/resources"
            java.mkdir(parents=True)
            resources.mkdir(parents=True)
            (java / "CleanupJob.java").write_text(
                "package com.acme; class CleanupJob { public void cleanup() {} }",
                encoding="utf-8",
            )
            (resources / "quartz.xml").write_text(
                """<beans>
  <bean id="cleanupJob" class="com.acme.CleanupJob"/>
  <bean id="jobDetail" class="org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean">
    <property name="targetObject" ref="cleanupJob"/>
    <property name="targetMethod" value="cleanup"/>
  </bean>
</beans>""",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(module / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertTrue(any(
            edge["edge_kind"] == "spring_runtime_active_entry"
            and edge["target"] == "com.acme.CleanupJob.cleanup"
            and edge["evidence"].get("xml_kind") == "spring_xml_quartz_method_invoking_job"
            for edge in spring["edges"]
        ))

    def test_spring_xml_runtime_active_entry_is_attached_to_graph_method(self):
        method = SimpleNamespace(symbol_id="m1", qualified_key="com.acme.CleanupJob.cleanup")
        graph = SimpleNamespace(methods_by_id={"m1": method})
        payload = {"adapters": [{
            "adapter": "spring_basic",
            "version": "1",
            "edges": [{
                "source": "framework:spring_xml_scheduled_task",
                "target": "com.acme.CleanupJob.cleanup",
                "edge_kind": "spring_runtime_active_entry",
                "confidence": "high",
            }],
        }]}

        stats = ingest_framework_payload(graph, payload)

        self.assertEqual(stats["matched_callback_edges"], 1)
        self.assertEqual(graph.framework_entry_symbols["m1"][0]["edge_kind"], "spring_runtime_active_entry")

    def test_spring_bean_method_binds_return_type_to_created_implementation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Config.java").write_text(
                "package com.acme; import org.springframework.context.annotation.Bean; "
                "import org.springframework.context.annotation.Configuration; "
                "@Configuration class Config { @Bean PaymentService paymentService() { "
                "return new PaymentServiceImpl(); } "
                "static class PaymentServiceImpl implements PaymentService {} }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        bean_edge = next(edge for edge in spring["edges"] if edge["edge_kind"] == "spring_bean_dispatch")
        self.assertEqual(bean_edge["source"], "com.acme.PaymentService")
        self.assertEqual(bean_edge["target"], "com.acme.PaymentServiceImpl")
        self.assertNotEqual(bean_edge["target"], "com.acme.Config")

    def test_unresolved_spring_bean_factory_is_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Config.java").write_text(
                "package com.acme; import org.springframework.context.annotation.Bean; "
                "class Config { @Bean PaymentService paymentService() { return createService(); } }",
                encoding="utf-8",
            )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertEqual(spring["status"], "partial")
        self.assertTrue(any(
            item["reason_code"] == "spring_bean_method_unresolved" for item in spring["findings"]
        ))

    def test_spring_autoconfiguration_resource_registrations_are_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java"
            spring_meta = module / "src/main/resources/META-INF/spring"
            java.mkdir(parents=True)
            spring_meta.mkdir(parents=True)
            (spring_meta / "org.springframework.boot.autoconfigure.AutoConfiguration.imports").write_text(
                "com.acme.NewAutoConfiguration\n", encoding="utf-8",
            )
            (module / "src/main/resources/META-INF/spring.factories").write_text(
                "org.springframework.boot.autoconfigure.EnableAutoConfiguration=\\\n"
                "com.acme.LegacyAutoConfiguration\n",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(java)}])

        spi = next(item for item in payload["adapters"] if item["adapter"] == "java_spi")
        kinds = {edge["edge_kind"] for edge in spi["edges"]}
        self.assertIn("spring_autoconfiguration_registration", kinds)
        self.assertIn("spring_factories_registration", kinds)

    def test_packaged_spring_listener_is_runtime_entry_when_business_starts_spring_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; import org.springframework.boot.SpringApplication; "
                "class Application { public static void main(String[] args) { "
                "SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            runtime_jar = module / "runtime.jar"
            with zipfile.ZipFile(runtime_jar, "w") as jar:
                jar.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=\\\n"
                    "com.vendor.RuntimeListener\n"
                    "org.springframework.boot.autoconfigure.EnableAutoConfiguration=\\\n"
                    "com.vendor.OptionalAutoConfiguration\n",
                )
            business_jar = module / "application.jar"
            with zipfile.ZipFile(business_jar, "w") as jar:
                jar.writestr("BOOT-INF/classes/com/acme/Application.class", b"application")
            business_sha = hashlib.sha256(business_jar.read_bytes()).hexdigest()
            runtime_sha = hashlib.sha256(runtime_jar.read_bytes()).hexdigest()
            payload = run_framework_adapters(
                [{"root": str(module / "src/main/java")}],
                artifact_catalog={"entries": [
                    {
                        "coord": "__business__",
                        "jar_path": str(business_jar),
                        "sha256": business_sha,
                    },
                    {
                        "coord": "com.vendor:runtime",
                        "jar_path": str(runtime_jar),
                        "artifact_entry": "BOOT-INF/lib/runtime.jar",
                        "sha256": runtime_sha,
                    },
                ]},
            )

        runtime = next(item for item in payload["adapters"] if item["adapter"] == "spring_runtime_artifact")
        callback = next(edge for edge in runtime["edges"] if edge["edge_kind"] == "spring_runtime_registered_callback")
        autoconfig = next(edge for edge in runtime["edges"] if edge["edge_kind"] == "spring_runtime_autoconfiguration_registration")
        self.assertEqual(callback["target"], "com.vendor.RuntimeListener.onApplicationEvent")
        self.assertEqual(callback["runtime_activation"], "active")
        self.assertEqual(autoconfig["runtime_activation"], "conditional")

        graph = SimpleNamespace(methods_by_id={})
        stats = ingest_framework_payload(graph, payload)
        self.assertEqual(stats["runtime_framework_entry_methods"], 1)
        self.assertIn("com.vendor.RuntimeListener.onApplicationEvent", graph.framework_runtime_entry_methods)

    def test_runtime_activation_requires_sha_bound_business_class_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            java = module / "src/main/java/com/acme"
            java.mkdir(parents=True)
            (java / "Application.java").write_text(
                "package com.acme; import org.springframework.boot.SpringApplication; "
                "class Application { public static void main(String[] args) { "
                "SpringApplication.run(Application.class, args); } }",
                encoding="utf-8",
            )
            business_jar = module / "application.jar"
            with zipfile.ZipFile(business_jar, "w") as jar:
                jar.writestr("BOOT-INF/classes/com/acme/Other.class", b"other")
            runtime_jar = module / "runtime.jar"
            with zipfile.ZipFile(runtime_jar, "w") as jar:
                jar.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener="
                    "com.vendor.RuntimeListener\n",
                )
            runtime_sha = hashlib.sha256(runtime_jar.read_bytes()).hexdigest()
            catalog = {"entries": [
                {
                    "coord": "__business__",
                    "jar_path": str(business_jar),
                    "sha256": hashlib.sha256(business_jar.read_bytes()).hexdigest(),
                },
                {
                    "coord": "com.vendor:runtime",
                    "jar_path": str(runtime_jar),
                    "artifact_entry": "BOOT-INF/lib/runtime.jar",
                    "sha256": runtime_sha,
                },
            ]}

            unverified = framework_adapter_module.run_runtime_spring_registration_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=catalog,
            )
            with zipfile.ZipFile(business_jar, "a") as jar:
                jar.writestr(
                    "BOOT-INF/classes/com/acme/Application.class",
                    b"application",
                )
            catalog["entries"][0]["sha256"] = hashlib.sha256(
                business_jar.read_bytes()
            ).hexdigest()
            verified = framework_adapter_module.run_runtime_spring_registration_adapter(
                [{"root": str(module / "src/main/java"), "owner_type": "business"}],
                artifact_catalog=catalog,
            )

        unverified_callback = next(
            edge for edge in unverified.edges
            if edge.edge_kind == "spring_runtime_registered_callback"
        )
        verified_callback = next(
            edge for edge in verified.edges
            if edge.edge_kind == "spring_runtime_registered_callback"
        )
        self.assertEqual(dict(unverified_callback.metadata)["runtime_activation"], "unproven")
        metadata = dict(verified_callback.metadata)
        self.assertEqual(metadata["runtime_activation"], "active")
        provenance = framework_adapter_module.thaw_evidence_value(
            metadata["framework_provenance"]
        )
        self.assertEqual(
            provenance["artifact_sha256"],
            runtime_sha,
        )
        self.assertEqual(provenance["artifact_entry"], "BOOT-INF/lib/runtime.jar")
        activation = provenance["business_activation"]
        self.assertEqual(len(activation), 1)
        self.assertEqual(activation[0]["business_entry"], "com.acme.Application.main")
        self.assertEqual(
            activation[0]["artifact_entry"],
            "BOOT-INF/classes/com/acme/Application.class",
        )
        self.assertEqual(
            activation[0]["artifact_sha256"],
            catalog["entries"][0]["sha256"],
        )
        self.assertEqual(
            activation[0]["authority"],
            "current_final_artifact_classfile",
        )

    def test_runtime_activation_rejects_catalog_sha_that_does_not_match_jar_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            business_jar = Path(tmp) / "application.jar"
            with zipfile.ZipFile(business_jar, "w") as jar:
                jar.writestr(
                    "BOOT-INF/classes/com/acme/Application.class",
                    b"actual-class-bytes",
                )
            activation = [{
                "business_entry": "com.acme.Application.main",
                "spring_application_run": True,
            }]
            catalog = {"entries": [{
                "coord": "__business__",
                "jar_path": str(business_jar),
                "sha256": "a" * 64,
            }]}

            verified = framework_adapter_module._verified_spring_boot_business_activation(
                activation,
                catalog,
            )

        self.assertEqual(verified, [])

    @unittest.skipUnless(shutil.which("javac") and shutil.which("javap"), "JDK tools required")
    def test_packaged_message_listener_adapter_registers_exact_business_callback(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            source = module / "compile-src"
            adapter = (
                source / "org/springframework/amqp/rabbit/listener/adapter/"
                "MessageListenerAdapter.java"
            )
            receiver = source / "com/acme/Receiver.java"
            application = source / "com/acme/Application.java"
            for path in (adapter, receiver, application):
                path.parent.mkdir(parents=True, exist_ok=True)
            adapter.write_text(
                "package org.springframework.amqp.rabbit.listener.adapter; "
                "public class MessageListenerAdapter { "
                "public MessageListenerAdapter(Object target, String method) {} }",
                encoding="utf-8",
            )
            receiver.write_text(
                "package com.acme; public class Receiver { "
                "public void handlePayload(String value) {} }",
                encoding="utf-8",
            )
            application.write_text(
                "package com.acme; "
                "import org.springframework.amqp.rabbit.listener.adapter.MessageListenerAdapter; "
                "public class Application { MessageListenerAdapter listenerAdapter(Receiver receiver) { "
                "return new MessageListenerAdapter(receiver, \"handlePayload\"); } }",
                encoding="utf-8",
            )
            classes = module / "classes"
            classes.mkdir()
            subprocess.run(
                ["javac", "-d", str(classes), str(adapter), str(receiver), str(application)],
                check=True,
                capture_output=True,
                text=True,
            )
            business_jar = module / "business.jar"
            with zipfile.ZipFile(business_jar, "w") as jar:
                for class_file in sorted(classes.rglob("*.class")):
                    relative = class_file.relative_to(classes).as_posix()
                    if relative.startswith("com/acme/"):
                        jar.write(class_file, relative)
                jar.writestr("com/acme/Boot.class", b"packaged-boot")
            business_sha = hashlib.sha256(business_jar.read_bytes()).hexdigest()
            source_root = module / "src/main/java/com/acme"
            source_root.mkdir(parents=True)
            (source_root / "Boot.java").write_text(
                "package com.acme; import org.springframework.boot.SpringApplication; "
                "class Boot { public static void main(String[] args) { "
                "SpringApplication.run(Boot.class, args); } }",
                encoding="utf-8",
            )

            payload = run_framework_adapters(
                [{"root": str(module / "src/main/java")}],
                artifact_catalog={"entries": [{
                    "coord": "__business__",
                    "jar_path": str(business_jar),
                    "evidence_source": "current_final_artifact",
                    "sha256": business_sha,
                }]},
            )

        runtime = next(
            item for item in payload["adapters"]
            if item["adapter"] == "spring_runtime_artifact"
        )
        callback = next(
            edge for edge in runtime["edges"]
            if edge["edge_kind"] == "spring_runtime_registered_callback"
        )
        self.assertEqual(callback["target"], "com.acme.Receiver.handlePayload")
        self.assertEqual(callback["target_descriptor"], "(Ljava/lang/String;)V")
        self.assertEqual(callback["runtime_activation"], "active")
        self.assertEqual(callback["provenance"]["coord"], "__business__")
        self.assertEqual(callback["provenance"]["registration_owner"], "com.acme.Application")
        self.assertEqual(callback["provenance"]["registration_member"], "listenerAdapter")
        self.assertEqual(callback["provenance"]["registration_instruction_offset"], 7)

    def test_dependency_test_source_does_not_activate_spring_boot_runtime_callbacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp)
            business = module / "app/src/main/java/com/acme"
            dependency_tests = module / "dep/src/test/java/com/vendor"
            business.mkdir(parents=True)
            dependency_tests.mkdir(parents=True)
            (business / "PlainApp.java").write_text(
                "package com.acme; class PlainApp { public static void main(String[] args) {} }",
                encoding="utf-8",
            )
            (dependency_tests / "DependencyTestApplication.java").write_text(
                "package com.vendor; import org.springframework.boot.SpringApplication; "
                "class DependencyTestApplication { public static void main(String[] args) { "
                "SpringApplication.run(DependencyTestApplication.class, args); } }",
                encoding="utf-8",
            )
            runtime_jar = module / "runtime.jar"
            with zipfile.ZipFile(runtime_jar, "w") as jar:
                jar.writestr(
                    "META-INF/spring.factories",
                    "org.springframework.context.ApplicationListener=com.vendor.RuntimeListener\n",
                )
            runtime_sha = hashlib.sha256(runtime_jar.read_bytes()).hexdigest()

            payload = run_framework_adapters(
                [
                    {"root": str(module / "app/src/main/java"), "owner_type": "business"},
                    {"root": str(module / "dep"), "owner_type": "dependency"},
                ],
                artifact_catalog={"entries": [{
                    "coord": "com.vendor:runtime",
                    "jar_path": str(runtime_jar),
                    "sha256": runtime_sha,
                }]},
            )

        runtime = next(item for item in payload["adapters"] if item["adapter"] == "spring_runtime_artifact")
        callback = next(edge for edge in runtime["edges"] if edge["edge_kind"] == "spring_runtime_registered_callback")
        self.assertEqual(callback["runtime_activation"], "unproven")
        self.assertEqual(callback["provenance"]["business_activation"], [])

    def test_source_framework_adapters_exclude_dependency_test_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp) / "dependency"
            main = module / "src/main/java/com/vendor"
            tests = module / "src/test/java/com/vendor"
            main.mkdir(parents=True)
            tests.mkdir(parents=True)
            (main / "CleanupJob.java").write_text(
                "package com.vendor; import org.springframework.scheduling.annotation.Scheduled; "
                "class CleanupJob { @Scheduled(fixedDelay=1000) public void cleanup() {} }",
                encoding="utf-8",
            )
            (tests / "DependencyTestJob.java").write_text(
                "package com.vendor; import org.springframework.scheduling.annotation.Scheduled; "
                "class DependencyTestJob { @Scheduled(fixedDelay=1000) public void testOnly() {} "
                "void proxy() { java.lang.reflect.Proxy.newProxyInstance(null, null, null); } }",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{
                "root": str(module),
                "owner_type": "dependency",
                "coord": "com.vendor:dependency",
            }])

        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        proxy = next(item for item in payload["adapters"] if item["adapter"] == "dynamic_proxy_basic")
        self.assertTrue(any(edge["target"] == "com.vendor.CleanupJob.cleanup" for edge in spring["edges"]))
        self.assertFalse(any("DependencyTestJob" in edge.get("target", "") for edge in spring["edges"]))
        self.assertFalse(any("src/test" in item.get("file", "") for item in proxy["findings"]))
        self.assertEqual(proxy["metrics"]["source_files_scanned"], 1)

    def test_active_runtime_registration_is_added_to_reverse_call_graph(self):
        app = SimpleNamespace(
            symbol_id="app", qualified_key="com.acme.Application.main",
            declared_qualified_key="com.acme.Application.main(String[])",
            declared_signature="(String[])", owner_type="business",
            owner_coord="BUSINESS", module="app", is_test=False,
        )
        listener = SimpleNamespace(
            symbol_id="listener", qualified_key="com.vendor.RuntimeListener.onApplicationEvent",
            declared_qualified_key="com.vendor.RuntimeListener.onApplicationEvent(Object)",
            declared_signature="(Object)", owner_type="dependency",
            owner_coord="com.vendor:runtime", module="runtime", is_test=False,
        )
        graph = SimpleNamespace(
            methods_by_id={"app": app, "listener": listener},
            reverse_edges={},
        )
        payload = {"adapters": [{
            "adapter": "spring_runtime_artifact",
            "version": "1",
            "edges": [{
                "source": "framework:spring-factories:org.springframework.context.ApplicationListener",
                "target": "com.vendor.RuntimeListener.onApplicationEvent",
                "edge_kind": "spring_runtime_registered_callback",
                "confidence": "high",
                "runtime_activation": "active",
                "conditions": [],
                "ambiguity": False,
                "provenance": {
                    "jar": "/runtime/runtime.jar",
                    "line": 1,
                    "business_activation": [{
                        "business_entry": "com.acme.Application.main",
                        "file": "/app/Application.java",
                        "spring_application_run": True,
                    }],
                },
            }],
        }]}

        stats = ingest_framework_payload(graph, payload)

        self.assertEqual(stats["framework_activation_linked_methods"], 1)
        self.assertIn("listener", graph.framework_activation_linked_symbols)
        linked = graph.reverse_edges["com.vendor.RuntimeListener.onApplicationEvent(Object)"]
        self.assertEqual(linked[0].caller_symbol_id, "app")
        self.assertEqual(linked[0].evidence_type, "spring_runtime_registered_callback")

    def test_edges_have_stable_schema_and_ambiguous_spring_dispatch_is_not_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            for name in ("One", "Two"):
                (root / f"{name}.java").write_text(
                    f"package com.acme; import org.springframework.stereotype.Service; "
                    f"@Service class {name} implements Plugin {{}}", encoding="utf-8"
                )
            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])
        spring = next(item for item in payload["adapters"] if item["adapter"] == "spring_basic")
        self.assertFalse(any(edge["edge_kind"] == "spring_bean_dispatch" for edge in spring["edges"]))
        self.assertTrue(any(item["reason_code"] == "AMBIGUOUS_FRAMEWORK_DISPATCH" for item in spring["findings"]))
        spi = next(item for item in payload["adapters"] if item["adapter"] == "java_spi")
        for edge in spi["edges"]:
            self.assertTrue({"adapter", "adapter_version", "evidence", "activation_conditions", "candidate_count", "ambiguity_reason"} <= set(edge))

    def test_dynamic_proxy_adapter_emits_callback_edge_and_registration_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "Handler.java").write_text(
                "package com.acme; "
                "import java.lang.reflect.InvocationHandler; "
                "import java.lang.reflect.Method; "
                "class Handler implements InvocationHandler { "
                "public Object invoke(Object proxy, Method method, Object[] args) { return null; } }",
                encoding="utf-8",
            )
            (root / "Factory.java").write_text(
                "package com.acme; "
                "import java.lang.reflect.Proxy; "
                "class Factory { Object build(Handler handler) { return Proxy.newProxyInstance("
                "Factory.class.getClassLoader(), new Class[]{Plugin.class}, handler); } }",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        adapter = next(item for item in payload["adapters"] if item["adapter"] == "dynamic_proxy_basic")
        self.assertEqual(adapter["status"], "complete")
        self.assertTrue(any(edge["edge_kind"] == "dynamic_proxy_callback" for edge in adapter["edges"]))
        self.assertTrue(any(item["reason_code"] == "dynamic_proxy_registration" for item in adapter["findings"]))

        graph = SimpleNamespace(
            methods_by_id={"m1": SimpleNamespace(symbol_id="m1", qualified_key="com.acme.Handler.invoke")}
        )
        ingest_framework_payload(graph, payload)
        self.assertEqual(graph.framework_entry_symbols, {})

    def test_unregistered_dynamic_proxy_handler_is_not_a_framework_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "DeadHandler.java").write_text(
                "package com.acme; import java.lang.reflect.*; "
                "class DeadHandler implements InvocationHandler { "
                "public Object invoke(Object proxy, Method method, Object[] args) { return null; } }",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        adapter = next(item for item in payload["adapters"] if item["adapter"] == "dynamic_proxy_basic")
        self.assertEqual(adapter["status"], "not_applicable")
        self.assertEqual(adapter["edges"], [])

    def test_declarative_http_client_adapter_emits_outbound_edge_for_feign_get_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "RemoteApi.java").write_text(
                "package com.acme; "
                "import org.springframework.cloud.openfeign.FeignClient; "
                "import org.springframework.web.bind.annotation.GetMapping; "
                "@FeignClient(name = \"demo\") "
                "interface RemoteApi { @GetMapping(\"/orders\") Order fetch(); }",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        adapter = next(item for item in payload["adapters"] if item["adapter"] == "declarative_http_client_basic")
        self.assertEqual(adapter["status"], "complete")
        self.assertTrue(any(edge["edge_kind"] == "declarative_http_client_outbound" for edge in adapter["edges"]))
        self.assertEqual(adapter["edges"][0]["source"], "com.acme.RemoteApi.fetch")
        self.assertTrue(any(item["reason_code"] == "declarative_http_client_registration" for item in adapter["findings"]))

        graph = SimpleNamespace(
            methods_by_id={"m1": SimpleNamespace(symbol_id="m1", qualified_key="com.acme.RemoteApi.fetch")}
        )
        ingest_framework_payload(graph, payload)
        self.assertEqual(graph.framework_entry_symbols, {})

    def test_feign_route_combines_class_and_method_request_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "src/main/java/com/acme"
            root.mkdir(parents=True)
            (root / "RemoteApi.java").write_text(
                "package com.acme; "
                "import org.springframework.cloud.openfeign.FeignClient; "
                "import org.springframework.web.bind.annotation.RequestMapping; "
                "import org.springframework.web.bind.annotation.GetMapping; "
                "@FeignClient(name=\"demo\") @RequestMapping(\"/api\") "
                "interface RemoteApi { @GetMapping(\"/orders\") String fetch(); }",
                encoding="utf-8",
            )

            payload = run_framework_adapters([{"root": str(Path(tmp) / "src/main/java")}])

        adapter = next(item for item in payload["adapters"] if item["adapter"] == "declarative_http_client_basic")
        edge = next(item for item in adapter["edges"] if item["source"] == "com.acme.RemoteApi.fetch")
        self.assertEqual(edge["provenance"]["request_mapping"], "/api/orders")


if __name__ == '__main__':
    unittest.main()
