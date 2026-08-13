import csv
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

from binary_decision_engine import BinaryDecisionBundle  # noqa: E402
from binary_first_model import ActiveSnapshot, RuntimeProfile  # noqa: E402
from binary_output import (  # noqa: E402
    BinaryOutputError,
    _aggregate_by_api,
    activate_binary_generation,
    write_binary_generation,
)
from binary_trace_engine import BinaryTraceBundle  # noqa: E402
from signature_utils import jvm_method_parameter_signature  # noqa: E402


class BinaryOutputTest(unittest.TestCase):
    def test_jvm_descriptor_is_presented_as_java_parameter_signature(self):
        self.assertEqual(jvm_method_parameter_signature("()I"), "()")
        self.assertEqual(
            jvm_method_parameter_signature("(Ljava/lang/String;[I[[Lcom/acme/Dto;)V"),
            "(java.lang.String,int[],com.acme.Dto[][])",
        )
        with self.assertRaisesRegex(ValueError, "invalid_method_descriptor"):
            jvm_method_parameter_signature("(I")

    def profile(self):
        required = RuntimeProfile.REQUIRED_FIELDS
        return RuntimeProfile({
            "target_jvm": {"vendor": "test", "major": 21},
            "runtime_platform_image_identity": "platform-1",
            "target_os": "linux",
            "target_arch": "amd64",
            "container_and_launcher_kind": "java-classpath",
            "ordered_runtime_path_entry_descriptors": [{
                "logical_location": "lib/api.jar", "content_sha256": "a" * 64,
                "path_kind": "classpath", "slot": 0, "loader_realm": "app",
            }],
            "loader_topology": {"app": {"parent": "platform"}},
            "runtime_code_source_origin_mapping_identity": "origins-1",
            "runtime_security_and_package_sealing_policy_identity": "security-1",
            "active_profile_identities": ["default"],
            "external_config_snapshot_identities": [],
            "agent_transformer_plugin_profile_identities": [],
            "business_entrypoint_profile": {"coverage_status": "complete", "methods": []},
            "runtime_class_closure_coverage_status": "complete",
            "resource_selection_coverage_status": "complete",
            "field_coverage": {key: "known" for key in required},
        })

    def bundles(self):
        context = "context-1"
        decision = {
            "observed_delta_identity": "observed-1",
            "disposition_obligation_identity": "obligation-1",
            "decision_identity": "decision-1",
            "decision_channel": "authoritative",
            "change_fact_identity": "change-1",
            "change_fact_status": "confirmed",
            "fact_kind": "method",
            "fact_scope": {
                "initiating_loader_realm_identity": "app",
                "class_name": "vendor/Api",
                "member_kind": "method",
                "member_name": "work",
                "descriptor": "()V",
            },
            "coverage_gaps": [],
        }
        assessment = {
            "projection_assessment_identity": "assessment-1",
            "decision_identity": "decision-1",
            "change_fact_identity": "change-1",
            "analysis_projection_status": "targetable",
            "projection_coverage_status": "complete",
            "target_identities": ["target-1"],
            "projection_obligation_keys": ["obligation-key-1"],
            "partial_projection_scopes": [],
        }
        projection = {
            "projection_identity": "projection-1",
            "projection_assessment_identity": "assessment-1",
            "projection_obligation_key": "obligation-key-1",
            "change_fact_identity": "change-1",
            "target_identity": "target-1",
        }
        snapshots = {
            "decision": ActiveSnapshot("decision", context, ("decision-1",)),
            "assessment": ActiveSnapshot("assessment", context, ("assessment-1",)),
            "formal_projection": ActiveSnapshot("formal_projection", context, ("projection-1",)),
            "candidate_projection": ActiveSnapshot("candidate_projection", context, ()),
        }
        decisions = BinaryDecisionBundle(
            context,
            (decision,),
            (),
            (),
            (assessment,),
            (projection,),
            (),
            snapshots,
            "complete",
            (),
            "decision-bundle-1",
        )
        formal = {
            "projection_identity": "projection-1",
            "decision_identity": "decision-1",
            "change_fact_identity": "change-1",
            "projection_assessment_identity": "assessment-1",
            "analysis_context_identity": context,
            "trace_result_identity": "trace-1",
            "reachability_status": "reachable",
            "analysis_status": "reachable",
            "is_reachable": True,
            "impact_conclusion": "probable_impact",
            "runtime_verification_status": "required_not_executed",
            "runtime_verification_executed_by_system": False,
            "path_set_complete": True,
            "exact_path_exists": True,
            "possible_path_exists": False,
        }
        traces = BinaryTraceBundle(
            context,
            (formal,),
            (),
            "trace-set-1",
            "complete",
            (),
            "trace-bundle-1",
        )
        return decisions, traces

    def test_writes_immutable_generation_with_four_dimensions_and_attachments(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            first = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            second = write_binary_generation(
                tmp,
                decisions,
                traces,
                profile,
                policy_identities={"projection_registry": "registry-1"},
            )
            activate_binary_generation(tmp, first, validation_result={
                "status": "passed",
                "result_generation_identity": first["result_generation_identity"],
                "validation_run_identity": "validation-1",
            })
            generation = Path(first["generation_directory"])
            manifest = json.loads((generation / "result_generation.json").read_text())
            active = json.loads((Path(tmp) / "active_binary_generation.json").read_text())
            formal = json.loads((generation / "binary_formal_results.json").read_text())
            attachment = json.loads((generation / "generation_attachments.json").read_text())
            with (generation / "binary_formal_results.csv").open(newline="") as handle:
                csv_rows = list(csv.DictReader(handle))
            actual_sidecar_identities = {
                name: hashlib.sha256((generation / name).read_bytes()).hexdigest()
                for name in manifest["sidecar_content_identities"]
            }

        self.assertEqual(first["result_generation_identity"], second["result_generation_identity"])
        self.assertEqual(active["result_generation_identity"], manifest["result_generation_identity"])
        self.assertEqual(attachment["result_generation_identity"], manifest["result_generation_identity"])
        self.assertEqual(attachment["formal_trace_result_identities"], ["trace-1"])
        by_api = formal["by_api"][0]
        self.assertEqual(by_api["reachability_status"], "reachable")
        self.assertEqual(by_api["impact_conclusion"], "probable_impact")
        self.assertEqual(by_api["runtime_verification_status"], "required_not_executed")
        self.assertTrue(by_api["path_set_complete"])
        self.assertEqual(csv_rows[0]["reachability_status"], "reachable")
        for name, expected in manifest["sidecar_content_identities"].items():
            self.assertEqual(actual_sidecar_identities[name], expected)

    def test_concurrent_identical_generation_publication_is_idempotent(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            def publish():
                return write_binary_generation(
                    tmp, decisions, traces, profile,
                    policy_identities={"projection_registry": "registry-1"},
                )

            with ThreadPoolExecutor(max_workers=4) as executor:
                manifests = list(executor.map(lambda _index: publish(), range(8)))
            identities = {
                item["result_generation_identity"] for item in manifests
            }
            generation_dirs = list((Path(tmp) / "binary_generations").iterdir())
            manifest = json.loads((
                generation_dirs[0] / "result_generation.json"
            ).read_text(encoding="utf-8"))

        self.assertEqual(len(identities), 1)
        self.assertEqual(len(generation_dirs), 1)
        self.assertEqual(manifest["result_generation_identity"], next(iter(identities)))

    def test_unreachable_api_keeps_runtime_verification_undetermined(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        formal = dict(traces.formal_results[0])
        formal.update({
            "reachability_status": "not_found_in_static_analysis",
            "analysis_status": "not_found_in_static_analysis",
            "is_reachable": False,
            "impact_conclusion": "inconclusive",
            "runtime_verification_status": "undetermined",
            "exact_path_exists": False,
        })
        unreachable_traces = replace(traces, formal_results=(formal,))

        by_api = _aggregate_by_api(decisions, unreachable_traces, profile)[0]

        self.assertEqual(
            by_api["runtime_verification_status"], "undetermined"
        )

    def test_api_runtime_verification_is_derived_from_reachability(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        inconsistent_formal = dict(traces.formal_results[0])
        inconsistent_formal["runtime_verification_status"] = "undetermined"

        by_api = _aggregate_by_api(
            decisions,
            replace(traces, formal_results=(inconsistent_formal,)),
            profile,
        )[0]

        self.assertEqual(
            by_api["runtime_verification_status"], "required_not_executed"
        )

    def test_large_path_sidecar_is_streamed_and_content_bound(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "facts.sqlite"
            source.write_bytes((b"binary-fact-block" * 65536) + b"tail")
            manifest = write_binary_generation(
                Path(tmp) / "output", decisions, traces, profile,
                policy_identities={"registry": "v1"},
                additional_sidecars={"facts.sqlite": source},
            )
            copied = Path(manifest["generation_directory"]) / "facts.sqlite"
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            copied_digest = hashlib.sha256(copied.read_bytes()).hexdigest()

        self.assertEqual(manifest["sidecar_content_identities"]["facts.sqlite"], expected)
        self.assertEqual(copied_digest, expected)

    def test_existing_generation_tampering_fails_without_moving_active_pointer(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            first = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            activate_binary_generation(tmp, first, validation_result={
                "status": "passed",
                "result_generation_identity": first["result_generation_identity"],
                "validation_run_identity": "validation-1",
            })
            active_before = (Path(tmp) / "active_binary_generation.json").read_bytes()
            generation = Path(first["generation_directory"])
            (generation / "binary_summary.json").write_text("tampered", encoding="utf-8")

            with self.assertRaises(BinaryOutputError) as error:
                write_binary_generation(
                    tmp, decisions, traces, profile,
                    policy_identities={"registry": "v1"},
                )

            active_after = (Path(tmp) / "active_binary_generation.json").read_bytes()
        self.assertEqual(error.exception.reason_code, "BINARY_GENERATION_IDENTITY_COLLISION")
        self.assertEqual(active_before, active_after)

    def test_generation_cannot_activate_without_independent_validation(self):
        profile = self.profile()
        decisions, traces = self.bundles()
        with tempfile.TemporaryDirectory() as tmp:
            manifest = write_binary_generation(
                tmp, decisions, traces, profile,
                policy_identities={"registry": "v1"},
            )
            with self.assertRaises(BinaryOutputError) as error:
                activate_binary_generation(tmp, manifest)
        self.assertEqual(
            error.exception.reason_code, "BINARY_GENERATION_VALIDATION_REQUIRED"
        )


if __name__ == "__main__":
    unittest.main()
