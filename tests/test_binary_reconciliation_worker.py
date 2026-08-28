from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import binary_pipeline as pipeline  # noqa: E402
import binary_reconciliation_worker as worker  # noqa: E402


SHA = "a" * 64


def capability_payload():
    return {
        "supported_loader_policy_versions": ["loader"],
        "supported_delegation_modes": ["parent_first"],
        "supported_security_policy_identities": ["security"],
        "supported_module_modes": ["classpath"],
        "supported_transformer_profile_identities": ["transformer"],
        "signed_artifacts_supported": True,
        "sealed_packages_supported": False,
        "closed_world_dispatch": True,
        "policy_version": "policy-v1",
    }


def worker_spec(root: Path):
    return {
        "schema": worker.SCHEMA,
        "store_path": str((root / "facts.sqlite").resolve()),
        "runtime_profile": {"side": "base"},
        "runtime_profile_identity": "1" * 64,
        "jdk_home": str((root / "jdk").resolve()),
        "platform_identity": "2" * 64,
        "asm_jar": str((root / "asm.jar").resolve()),
        "analysis_context_identity": "3" * 64,
        "capability_policy": capability_payload(),
        "capability_policy_identity": "4" * 64,
        "additional_initial_classes": ["a/A", "b/B"],
        "retain_record_kinds": ["class_definition", "provider_binding"],
        "compiled_asm_helper_binding": None,
        "compiled_definition_helper_binding": None,
    }


def result_payload(*, context="3" * 64, profile="1" * 64):
    return {
        "analysis_context_identity": context,
        "runtime_profile_identity": profile,
        "universe_identity": "5" * 64,
        "provider_bindings": [{"provider": "p"}],
        "class_definitions": [],
        "member_resolutions": [],
        "dispatch_resolutions": [],
        "type_resolutions": [],
        "class_initialization_resolutions": [],
        "linkage_resolutions": [],
        "resource_selections": [],
        "coverage_status": "complete",
        "coverage_gaps": [],
        "identity": "6" * 64,
    }


class BinaryReconciliationWorkerContractTest(unittest.TestCase):
    def test_scalar_and_spec_validation_exhausts_fail_closed_boundaries(self):
        self.assertEqual(worker._required_identity(SHA, "identity"), SHA)
        for value in (None, "", "a" * 63, "g" * 64):
            with self.subTest(identity=value), self.assertRaises(ValueError):
                worker._required_identity(value, "identity")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            absolute = str((root / "value").resolve())
            self.assertEqual(
                worker._required_absolute_path(absolute, "path"),
                Path(absolute),
            )
            for value in (None, "", "relative", f"{root}/child/../value"):
                with self.subTest(path=value), self.assertRaises(ValueError):
                    worker._required_absolute_path(value, "path")

            valid = worker_spec(root)
            asm_binding = object()
            definition_binding = object()
            with patch.object(
                worker,
                "compiled_asm_helper_binding_from_mapping",
                return_value=asm_binding,
            ), patch.object(
                worker,
                "compiled_definition_helper_binding_from_mapping",
                return_value=definition_binding,
            ):
                normalized = worker._spec(valid)
                self.assertIsNone(normalized["compiled_asm_helper_binding"])
                self.assertIsNone(
                    normalized["compiled_definition_helper_binding"]
                )
                with_bindings = deepcopy(valid)
                with_bindings["compiled_asm_helper_binding"] = {"binding": 1}
                with_bindings["compiled_definition_helper_binding"] = {
                    "binding": 2
                }
                normalized = worker._spec(with_bindings)
                self.assertIs(
                    normalized["compiled_asm_helper_binding"], asm_binding
                )
                self.assertIs(
                    normalized["compiled_definition_helper_binding"],
                    definition_binding,
                )

            invalid_documents = []
            invalid_documents.append(None)
            missing = deepcopy(valid)
            missing.pop("schema")
            invalid_documents.append(missing)
            changed_schema = deepcopy(valid)
            changed_schema["schema"] = "changed"
            invalid_documents.append(changed_schema)
            bad_profile = deepcopy(valid)
            bad_profile["runtime_profile"] = []
            invalid_documents.append(bad_profile)
            bad_identity = deepcopy(valid)
            bad_identity["runtime_profile_identity"] = "bad"
            invalid_documents.append(bad_identity)
            bad_capability_type = deepcopy(valid)
            bad_capability_type["capability_policy"] = []
            invalid_documents.append(bad_capability_type)
            bad_capability_fields = deepcopy(valid)
            bad_capability_fields["capability_policy"].pop("policy_version")
            invalid_documents.append(bad_capability_fields)
            for field in worker._CAPABILITY_FIELDS[:5]:
                for raw in (None, [1], [""]):
                    changed = deepcopy(valid)
                    changed["capability_policy"][field] = raw
                    invalid_documents.append(changed)
            changed = deepcopy(valid)
            changed["capability_policy"]["signed_artifacts_supported"] = 1
            invalid_documents.append(changed)
            for raw in (None, ""):
                changed = deepcopy(valid)
                changed["capability_policy"]["policy_version"] = raw
                invalid_documents.append(changed)
            for field in (
                "compiled_asm_helper_binding",
                "compiled_definition_helper_binding",
            ):
                changed = deepcopy(valid)
                changed[field] = "invalid"
                invalid_documents.append(changed)
            for field in ("additional_initial_classes", "retain_record_kinds"):
                for raw in (None, [1], [""], ["b", "a"], ["a", "a"]):
                    changed = deepcopy(valid)
                    changed[field] = raw
                    invalid_documents.append(changed)

            for index, document in enumerate(invalid_documents):
                with self.subTest(case=index), self.assertRaises(ValueError):
                    worker._spec(document)

    def test_result_projection_and_worker_run_preserve_exact_bindings(self):
        raw_result = SimpleNamespace(
            analysis_context_identity="3" * 64,
            runtime_profile_identity="1" * 64,
            universe_identity="5" * 64,
            coverage_status="complete",
            coverage_gaps=("gap",),
            identity="6" * 64,
            **{
                field: ({"kind": field},)
                for field in worker._RESULT_COLLECTION_FIELDS
            },
        )
        projected = worker._result_mapping(raw_result)
        self.assertEqual(projected["coverage_gaps"], ["gap"])
        self.assertEqual(
            projected["provider_bindings"], [{"kind": "provider_bindings"}]
        )

        normalized = {
            **worker_spec(Path("/private/reconciliation-worker-test")),
            "store_path": Path("/private/reconciliation-worker-test/facts.sqlite"),
            "jdk_home": Path("/private/reconciliation-worker-test/jdk"),
            "asm_jar": Path("/private/reconciliation-worker-test/asm.jar"),
            "capability_policy": capability_payload(),
        }
        asm_binding = object()
        definition_binding = object()
        normalized["compiled_asm_helper_binding"] = asm_binding
        normalized["compiled_definition_helper_binding"] = definition_binding

        class FakeProfile:
            identity = normalized["runtime_profile_identity"]

            def __init__(self, payload):
                self.payload = payload

        class FakeCapability:
            identity = normalized["capability_policy_identity"]

            def __init__(self, **payload):
                self.payload = payload

        class FakeConnection:
            def __init__(self, existing=False):
                self.existing = existing
                self.in_transaction = False

            def execute(self, query):
                if query == "BEGIN":
                    self.in_transaction = True
                    return SimpleNamespace(fetchone=lambda: None)
                return SimpleNamespace(
                    fetchone=lambda: (1,) if self.existing else None
                )

            def commit(self):
                self.in_transaction = False

            def rollback(self):
                self.in_transaction = False

        stores = []

        class FakeStore:
            def __init__(self, _path, existing=False):
                self.connection = FakeConnection(existing)
                self.closed = False
                stores.append(self)

            def close(self):
                self.closed = True

        class FakeReconciler:
            def __init__(self, *_args, **_kwargs):
                pass

            def reconcile(self, **_kwargs):
                return raw_result

        installed = []
        verified = []
        with patch.object(worker, "_spec", return_value=normalized), patch.object(
            worker, "RuntimeProfile", FakeProfile
        ), patch.object(
            worker, "RuntimeCapabilityPolicy", FakeCapability
        ), patch.object(
            worker,
            "capture_parser_identity_binding",
            return_value="parser-binding",
        ), patch.object(
            worker,
            "install_compiled_asm_helper_binding",
            side_effect=lambda value: installed.append(("asm", value)),
        ), patch.object(
            worker,
            "install_compiled_definition_helper_binding",
            side_effect=lambda value: installed.append(("definition", value)),
        ), patch.object(
            worker,
            "verify_compiled_asm_helper_binding",
            side_effect=lambda value: verified.append(("asm", value)),
        ), patch.object(
            worker,
            "verify_compiled_definition_helper_binding",
            side_effect=lambda value: verified.append(("definition", value)),
        ), patch.object(
            worker,
            "verify_parser_identity_binding",
            side_effect=lambda value: verified.append(("parser", value)),
        ), patch.object(
            worker,
            "JdkPlatformImage",
            return_value=SimpleNamespace(identity=normalized["platform_identity"]),
        ), patch.object(worker, "BinaryFactStore", FakeStore), patch.object(
            worker, "RuntimeReconciler", FakeReconciler
        ):
            response = worker.run({})

        self.assertEqual(response["status"], "passed")
        self.assertEqual([name for name, _value in installed], ["asm", "definition"])
        self.assertEqual(
            [name for name, _value in verified], ["asm", "definition", "parser"]
        )
        self.assertTrue(stores[-1].closed)

        without_bindings = dict(normalized)
        without_bindings["compiled_asm_helper_binding"] = None
        without_bindings["compiled_definition_helper_binding"] = None

        # Keep the production class symbol at the call site once so the
        # structural gate proves the worker delegates to the real reconciler
        # boundary even though the expensive body is isolated here.
        stores.clear()

        def initialize_reconciler(instance, store, *_args, **_kwargs):
            instance.store = store

        with patch.object(worker, "_spec", return_value=without_bindings), patch.object(
            worker, "RuntimeProfile", FakeProfile
        ), patch.object(
            worker, "RuntimeCapabilityPolicy", FakeCapability
        ), patch.object(
            worker, "capture_parser_identity_binding", return_value="parser"
        ), patch.object(
            worker,
            "JdkPlatformImage",
            return_value=SimpleNamespace(identity=normalized["platform_identity"]),
        ), patch.object(worker, "BinaryFactStore", FakeStore), patch.object(
            worker.RuntimeReconciler, "__init__", new=initialize_reconciler
        ), patch.object(
            worker.RuntimeReconciler, "_reconcile", return_value=raw_result
        ), patch.object(worker, "verify_parser_identity_binding"):
            self.assertEqual(worker.run({})["status"], "passed")
        self.assertTrue(stores[-1].closed)

        # Optional compiled-helper transport is never authoritative. Reuse
        # failure must continue with exact local compilation and skip its proof.
        installed.clear()
        verified.clear()
        stores.clear()
        with patch.object(worker, "_spec", return_value=normalized), patch.object(
            worker, "RuntimeProfile", FakeProfile
        ), patch.object(
            worker, "RuntimeCapabilityPolicy", FakeCapability
        ), patch.object(
            worker,
            "capture_parser_identity_binding",
            return_value="parser-binding",
        ), patch.object(
            worker,
            "install_compiled_asm_helper_binding",
            side_effect=worker.BinaryAsmError("ASM_REUSE_FAILED", "expected"),
        ), patch.object(
            worker,
            "install_compiled_definition_helper_binding",
            side_effect=worker.ClassDefinitionVerifierError(
                "DEFINITION_REUSE_FAILED", "expected"
            ),
        ), patch.object(
            worker, "verify_parser_identity_binding"
        ), patch.object(
            worker,
            "JdkPlatformImage",
            return_value=SimpleNamespace(identity=normalized["platform_identity"]),
        ), patch.object(worker, "BinaryFactStore", FakeStore), patch.object(
            worker, "RuntimeReconciler", FakeReconciler
        ), patch.object(
            worker, "verify_compiled_asm_helper_binding"
        ) as verify_asm, patch.object(
            worker, "verify_compiled_definition_helper_binding"
        ) as verify_definition:
            self.assertEqual(worker.run({})["status"], "passed")
        verify_asm.assert_not_called()
        verify_definition.assert_not_called()
        self.assertTrue(stores[-1].closed)

        with patch.object(
            worker, "_spec", return_value=without_bindings
        ), patch.object(
            worker,
            "RuntimeProfile",
            return_value=SimpleNamespace(identity="wrong-profile"),
        ), self.assertRaisesRegex(ValueError, "runtime profile identity"):
            worker.run({})

        with patch.object(worker, "_spec", return_value=without_bindings), patch.object(
            worker, "RuntimeProfile", FakeProfile
        ), patch.object(
            worker,
            "RuntimeCapabilityPolicy",
            return_value=SimpleNamespace(identity="wrong-capability"),
        ), self.assertRaisesRegex(ValueError, "runtime capability identity"):
            worker.run({})

        with patch.object(worker, "_spec", return_value=without_bindings), patch.object(
            worker, "RuntimeProfile", FakeProfile
        ), patch.object(
            worker, "RuntimeCapabilityPolicy", FakeCapability
        ), patch.object(
            worker, "capture_parser_identity_binding", return_value="parser"
        ), patch.object(
            worker, "JdkPlatformImage", return_value=SimpleNamespace(identity="wrong")
        ), self.assertRaisesRegex(ValueError, "platform identity"):
            worker.run({})

        stores.clear()
        with patch.object(worker, "_spec", return_value=without_bindings), patch.object(
            worker, "RuntimeProfile", FakeProfile
        ), patch.object(
            worker, "RuntimeCapabilityPolicy", FakeCapability
        ), patch.object(
            worker, "capture_parser_identity_binding", return_value="parser"
        ), patch.object(
            worker,
            "JdkPlatformImage",
            return_value=SimpleNamespace(identity=normalized["platform_identity"]),
        ), patch.object(
            worker,
            "BinaryFactStore",
            side_effect=lambda path: FakeStore(path, existing=True),
        ), self.assertRaisesRegex(ValueError, "already contains reconciliation"):
            worker.run({})
        self.assertTrue(stores[-1].closed)

    def test_worker_main_serializes_success_and_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input.json"
            target = root / "output.json"
            source.write_text("{}", encoding="utf-8")
            written = []
            with patch.object(
                worker, "run", return_value={"schema": worker.SCHEMA, "status": "passed"}
            ), patch.object(
                worker,
                "write_json_streaming_atomic",
                side_effect=lambda path, value, **_kwargs: written.append((path, value)),
            ):
                self.assertEqual(
                    worker.main(["--input", str(source), "--output", str(target)]),
                    0,
                )
            self.assertEqual(written[-1][1]["status"], "passed")

            written.clear()
            with patch.object(
                worker, "run", side_effect=RuntimeError("expected failure")
            ), patch.object(
                worker,
                "write_json_streaming_atomic",
                side_effect=lambda path, value, **_kwargs: written.append((path, value)),
            ):
                self.assertEqual(
                    worker.main(["--input", str(source), "--output", str(target)]),
                    1,
                )
            self.assertEqual(written[-1][1]["status"], "failed")
            self.assertEqual(written[-1][1]["failure"]["error_type"], "RuntimeError")


class ParallelRuntimeReconciliationContractTest(unittest.TestCase):
    def test_worker_count_and_result_decoder_cover_resource_and_shape_matrix(self):
        high_memory = 8 * 1024 * 1024 * 1024
        threshold = pipeline._PARALLEL_RECONCILIATION_MIN_CLASSES_PER_SIDE
        self.assertEqual(
            pipeline._runtime_reconciliation_worker_count(
                threshold, threshold, cpu_count=8,
                available_memory_bytes=high_memory,
            )[0],
            2,
        )
        for base, current, cpus, memory in (
            (threshold - 1, threshold, 8, high_memory),
            (threshold, threshold, 3, high_memory),
            (threshold, threshold, 8, None),
            (threshold, threshold, 8, 1),
            (-1, threshold, 8, high_memory),
        ):
            with self.subTest(values=(base, current, cpus, memory)):
                if memory is None:
                    with patch.object(
                        pipeline,
                        "system_available_memory_bytes",
                        side_effect=OSError("unavailable"),
                    ):
                        selected, observed = (
                            pipeline._runtime_reconciliation_worker_count(
                                base, current, cpu_count=cpus,
                                available_memory_bytes=memory,
                            )
                        )
                else:
                    selected, observed = pipeline._runtime_reconciliation_worker_count(
                        base, current, cpu_count=cpus,
                        available_memory_bytes=memory,
                    )
                self.assertEqual(selected, 1)
                self.assertEqual(observed, memory)
        with patch.object(pipeline.os, "cpu_count", return_value=None), patch.object(
            pipeline, "system_available_memory_bytes", return_value=high_memory
        ):
            self.assertEqual(
                pipeline._runtime_reconciliation_worker_count(threshold, threshold)[0],
                1,
            )
        with patch.object(pipeline.os, "cpu_count", return_value=8):
            self.assertEqual(
                pipeline._runtime_reconciliation_worker_count(
                    threshold, threshold, available_memory_bytes=high_memory
                )[0],
                2,
            )

        capability = SimpleNamespace(**{
            **capability_payload(),
            "supported_loader_policy_versions": ("loader",),
        })
        encoded = pipeline._runtime_capability_worker_payload(capability)
        self.assertEqual(encoded["supported_loader_policy_versions"], ["loader"])
        self.assertIs(encoded["signed_artifacts_supported"], True)

        valid = result_payload()
        decoded = pipeline._runtime_reconciliation_from_worker(
            valid,
            expected_context_identity=valid["analysis_context_identity"],
            expected_profile_identity=valid["runtime_profile_identity"],
        )
        self.assertEqual(decoded.provider_bindings, ({"provider": "p"},))

        invalid_values = [None, {**valid, "extra": True}]
        for field, replacement in (
            ("analysis_context_identity", "wrong"),
            ("runtime_profile_identity", "wrong"),
            ("universe_identity", "bad"),
            ("identity", "bad"),
            ("coverage_status", "unknown"),
            ("coverage_gaps", None),
            ("coverage_gaps", [1]),
            ("coverage_gaps", [""]),
            ("coverage_gaps", ["b", "a"]),
            ("coverage_gaps", ["a", "a"]),
            ("provider_bindings", None),
            ("provider_bindings", [1]),
        ):
            changed = deepcopy(valid)
            changed[field] = replacement
            invalid_values.append(changed)
        for index, value in enumerate(invalid_values):
            with self.subTest(case=index), self.assertRaises(
                pipeline.BinaryPipelineError
            ):
                pipeline._runtime_reconciliation_from_worker(
                    value,
                    expected_context_identity=valid["analysis_context_identity"],
                    expected_profile_identity=valid["runtime_profile_identity"],
                )

    def test_parallel_worker_transport_is_exact_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            jdk = root / "jdk"
            other_jdk = root / "other-jdk"
            profile_base = SimpleNamespace(payload={"side": "base"}, identity="1" * 64)
            profile_current = SimpleNamespace(
                payload={"side": "current"}, identity="2" * 64
            )
            platform_base = SimpleNamespace(
                jdk_home=jdk, identity="3" * 64
            )
            platform_current = SimpleNamespace(
                jdk_home=jdk, identity="4" * 64
            )
            capability = SimpleNamespace(
                **capability_payload(), identity="5" * 64
            )

            asm_captures = []
            definition_captures = []

            def capture_asm(**kwargs):
                asm_captures.append(kwargs["jdk_home"])
                return SimpleNamespace(to_mapping=lambda: {"asm": "binding"})

            def capture_definition(platform):
                definition_captures.append(platform.jdk_home)
                return SimpleNamespace(
                    to_mapping=lambda: {"definition": "binding"}
                )

            response_mode = {"value": "passed"}

            def managed(command, **_kwargs):
                output = Path(command[command.index("--output") + 1])
                source = Path(command[command.index("--input") + 1])
                request = json.loads(source.read_text(encoding="utf-8"))
                mode = response_mode["value"]
                if mode == "invalid-json":
                    output.write_text("{", encoding="utf-8")
                    return SimpleNamespace(returncode=0, stderr="invalid")
                if mode == "non-mapping":
                    output.write_text("[]", encoding="utf-8")
                    return SimpleNamespace(returncode=0, stderr="list")
                if mode == "failed":
                    payload = {
                        "schema": worker.SCHEMA,
                        "status": "failed",
                        "failure": {"detail": "expected"},
                    }
                    output.write_text(json.dumps(payload), encoding="utf-8")
                    return SimpleNamespace(returncode=1, stderr="failed")
                if mode == "wrong-schema":
                    payload = {"schema": "wrong", "status": "passed"}
                    output.write_text(json.dumps(payload), encoding="utf-8")
                    return SimpleNamespace(returncode=0, stderr="schema")
                if mode == "wrong-status":
                    payload = {"schema": worker.SCHEMA, "status": "unknown"}
                    output.write_text(json.dumps(payload), encoding="utf-8")
                    return SimpleNamespace(returncode=0, stderr="status")
                payload = {
                    "schema": worker.SCHEMA,
                    "status": "passed",
                    "result": result_payload(
                        profile=request["runtime_profile_identity"]
                    ),
                }
                output.write_text(json.dumps(payload), encoding="utf-8")
                return SimpleNamespace(returncode=0, stderr="")

            arguments = dict(
                temporary_directory=root,
                base_store_path=root / "base.sqlite",
                current_store_path=root / "current.sqlite",
                base_profile=profile_base,
                current_profile=profile_current,
                base_platform=platform_base,
                current_platform=platform_current,
                asm_jar=root / "asm.jar",
                analysis_context_identity="3" * 64,
                capability=capability,
                additional_initial_classes=("b/B", "", "a/A", "a/A"),
                retained_record_kinds=("provider_binding", "", "provider_binding"),
            )
            with patch.object(
                pipeline, "capture_compiled_asm_helper_binding", side_effect=capture_asm
            ), patch.object(
                pipeline,
                "capture_compiled_definition_helper_binding",
                side_effect=capture_definition,
            ), patch.object(
                pipeline, "run_managed_subprocess", side_effect=managed
            ):
                base, current = pipeline._run_parallel_runtime_reconciliation(
                    **arguments
                )
            self.assertEqual(base.runtime_profile_identity, profile_base.identity)
            self.assertEqual(current.runtime_profile_identity, profile_current.identity)
            self.assertEqual(asm_captures, [jdk])
            self.assertEqual(definition_captures, [jdk])

            distinct_arguments = dict(arguments)
            distinct_arguments["current_platform"] = SimpleNamespace(
                jdk_home=other_jdk, identity=platform_current.identity
            )
            with patch.object(
                pipeline,
                "capture_compiled_asm_helper_binding",
                side_effect=pipeline.BinaryAsmError("EXPECTED", "fallback"),
            ), patch.object(
                pipeline,
                "capture_compiled_definition_helper_binding",
                side_effect=pipeline.ClassDefinitionVerifierError(
                    "EXPECTED", "fallback"
                ),
            ), patch.object(
                pipeline, "run_managed_subprocess", side_effect=managed
            ):
                base, current = pipeline._run_parallel_runtime_reconciliation(
                    **distinct_arguments
                )
            self.assertEqual(base.coverage_status, "complete")
            self.assertEqual(current.coverage_status, "complete")

            for mode, reason in (
                ("invalid-json", "BINARY_RECONCILIATION_WORKER_OUTPUT_INVALID"),
                ("non-mapping", "BINARY_RECONCILIATION_WORKER_FAILED"),
                ("failed", "BINARY_RECONCILIATION_WORKER_FAILED"),
                ("wrong-schema", "BINARY_RECONCILIATION_WORKER_FAILED"),
                ("wrong-status", "BINARY_RECONCILIATION_WORKER_FAILED"),
            ):
                response_mode["value"] = mode
                with self.subTest(mode=mode), patch.object(
                    pipeline,
                    "capture_compiled_asm_helper_binding",
                    side_effect=pipeline.BinaryAsmError("EXPECTED", "fallback"),
                ), patch.object(
                    pipeline,
                    "capture_compiled_definition_helper_binding",
                    side_effect=pipeline.ClassDefinitionVerifierError(
                        "EXPECTED", "fallback"
                    ),
                ), patch.object(
                    pipeline, "run_managed_subprocess", side_effect=managed
                ), self.assertRaises(pipeline.BinaryPipelineError) as raised:
                    pipeline._run_parallel_runtime_reconciliation(
                        **distinct_arguments
                    )
                self.assertEqual(raised.exception.reason_code, reason)


if __name__ == "__main__":
    unittest.main()
