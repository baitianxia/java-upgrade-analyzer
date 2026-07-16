import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import test_round_retrospective as retro  # noqa: E402


def clean_real_payload(*, newly_observed=None):
    return {
        "status": "passed",
        "results": [{
            "case": "sample",
            "status": "passed",
            "project_root": "/tmp/sample",
            "project_asset_health": {"git_revision": "a" * 40, "git_dirty": False},
            "api_coverage_complete": True,
            "complete": True,
            "api_population": 1,
            "apis_selected": 1,
            "apis_accounted": 1,
            "coverage_ratio": 1.0,
            "result_audit": {"failures": [], "unverified": 0},
            "oracle_audit": {
                "selected": 1,
                "verified": 1,
                "incorrect": 0,
                "unverified": 0,
                "oracle_conflicts": 0,
                "missing_identity_count": 0,
                "duplicate_identity_count": 0,
                "extra_identity_count": 0,
                "invalid_provenance_count": 0,
                "analyzer_extra_identity_count": 0,
                "analyzer_duplicate_identity_count": 0,
                "analyzer_conflict_identity_count": 0,
                "blocking": False,
            },
            "edge_truth": {
                "complete": True,
                "blocking": False,
                "errors": [],
                "counts": {
                    "oracle_edge_count": 1,
                    "analyzer_edge_count": 1,
                    "edge_reconciliation_row_count": 2,
                    "edge_truth_correct_count": 2,
                    "edge_truth_missing_count": 0,
                    "edge_truth_extra_count": 0,
                    "edge_truth_identity_mismatch_count": 0,
                    "edge_truth_provenance_invalid_count": 0,
                    "edge_truth_oracle_conflict_count": 0,
                },
            },
            "topology_coverage": {
                "complete": True,
                "newly_observed": list(newly_observed or []),
                "missing": [],
            },
            "performance_envelope": {
                "within_budget": True,
                "elapsed_seconds": 12.5,
                "oracle_timed_out": False,
                "oracle_interrupted": False,
                "oracle_parse_failure_count": 0,
            },
            "performance_budget_seconds": 100.0,
        }],
    }


def audit_payload(*signals, real=None):
    real = real or clean_real_payload()
    return {
        "status": "signals_found" if signals else "clean",
        "summary": {
            "signal_count": len(signals),
            "blocking_signals": sum(bool(item.get("blocking")) for item in signals),
            "non_blocking_signals": sum(not bool(item.get("blocking")) for item in signals),
            "fixture_debt": sum(
                bool(item.get("blocking")) and not item.get("fixture_status")
                for item in signals
            ),
        },
        "signals": list(signals),
        "sources": [{"payload_sha256": retro.payload_sha256(real)}],
    }


def rotation_action():
    return {
        "decision": "rotate",
        "project": "next-framework-callback-project",
        "rationale": "cover runtime activation topology absent from the converged project",
        "target_topologies": ["framework_runtime_activation"],
    }


def p1_signal(message="wrong conclusion"):
    return {
        "signal_type": "correctness_failure",
        "severity": "P1",
        "blocking": True,
        "case": "sample",
        "step": "step5",
        "message": message,
        "fixture_status": "fixed",
    }


def complete_review(finding_id, **overrides):
    review = {
        "finding_id": finding_id,
        "root_cause_family": "evidence_identity",
        "escape_reason": "previous matrix did not combine nested owner and overload identity",
        "resolution_scope": "architecture",
        "regression_test": (
            "tests.test_step5_evidence_model.EvidenceModelTest."
            "test_collector_batch_requires_identity_and_valid_sha"
        ),
        "optimization_action": "unify evidence identity before graph traversal",
        "status": "fixed",
        "architecture_review": False,
        "capability_family": "canonical_evidence_identity",
        "invariant_id": "canonical_owner_member_descriptor_identity",
        "audited_production_paths": [
            "scripts/exhaustive_api_oracle.py",
            "scripts/final_artifact_edge_oracle.py",
            "scripts/signature_utils.py",
            "scripts/step5_evidence_ingestion.py",
            "scripts/step5_evidence_model.py",
            "scripts/third_party_jdeps_oracle.py",
            "scripts/third_party_jdk_oracle.py",
        ],
        "generalized_regression_tests": [
            "tests.test_step5_evidence_model.EvidenceModelTest."
            "test_collector_batch_requires_identity_and_valid_sha"
        ],
        "negative_regression_tests": [
            "tests.test_step5_evidence_model.EvidenceModelTest."
            "test_collector_batch_serialization_is_deterministic"
        ],
        "mutation_tests": [
            "tests.test_exhaustive_api_oracle.ExhaustiveApiOracleTest."
            "test_two_authority_gate_requires_same_conclusion"
        ],
        "cross_project_guards": ["ruoyi-full-artifact-discovery"],
        "architecture_decision": "",
    }
    review.update(overrides)
    return review


class TestRoundRetrospectiveTest(unittest.TestCase):
    def test_clean_converged_round_recommends_rotation(self):
        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(), reviews=[], history=[],
            next_action=rotation_action(),
        )

        self.assertEqual(retro.evaluate_retrospective(result), [])
        self.assertEqual(result["decision"], "rotate")
        self.assertEqual(result["summary"]["new_p0_p1_findings"], 0)
        self.assertTrue(result["evidence"]["oracle_complete"])
        self.assertTrue(result["evidence"]["performance_complete"])
        self.assertTrue(result["evidence"]["project_provenance_complete"])
        self.assertEqual(result["optimization_backlog"], [])

    def test_guard_matrix_topologies_are_stabilized_and_auto_rotate(self):
        real = clean_real_payload(newly_observed=["business_direct"])
        real["results"][0]["case_mode"] = "guard"

        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            reviews=[],
            history=[],
        )

        self.assertEqual(retro.evaluate_retrospective(result), [])
        self.assertEqual(result["decision"], "rotate")
        self.assertEqual(result["coverage"]["newly_observed"], [])
        self.assertNotEqual(result["next_action"]["project"], "sample")
        self.assertTrue(result["next_action"]["target_topologies"])

    def test_pinned_guard_contract_accepts_semantic_only_oracle(self):
        real = clean_real_payload()
        result = real["results"][0]
        result["oracle_audit"] = {}
        result["guard_contract"] = {
            "passed": True,
            "errors": [],
            "api_count": 1,
            "expected_physical_edge_count": 0,
            "expected_semantic_reference_count": 1,
        }
        result["edge_truth"]["counts"].update({
            "oracle_edge_count": 0,
            "analyzer_edge_count": 0,
            "edge_reconciliation_row_count": 0,
            "edge_truth_correct_count": 0,
            "semantic_reference_count": 1,
        })

        retrospective = retro.build_retrospective(
            real,
            audit_payload(real=real),
            reviews=[],
            history=[],
            next_action=rotation_action(),
        )

        self.assertTrue(retrospective["evidence"]["oracle_complete"])

    def test_new_topology_keeps_project_as_guard_before_rotation(self):
        real = clean_real_payload(newly_observed=["framework_callback"])
        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            reviews=[],
            history=[],
        )

        self.assertEqual(retro.evaluate_retrospective(result), [])
        self.assertEqual(result["decision"], "guard")
        self.assertEqual(result["coverage"]["newly_observed"], ["framework_callback"])

    def test_project_guard_scope_uses_same_retrospective_history_as_global_coverage(self):
        real = clean_real_payload()
        real["results"][0]["topology_coverage"] = {
            "complete": True,
            "observed": ["business_direct", "framework_callback"],
            "newly_observed": ["framework_callback"],
            "missing": [],
        }

        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            reviews=[],
            history=[],
        )

        self.assertEqual(retro.evaluate_retrospective(result), [])
        self.assertEqual(
            result["cases"][0]["newly_observed_topologies"],
            ["business_direct", "framework_callback"],
        )

    def test_topology_already_seen_in_history_is_not_new_again(self):
        real = clean_real_payload(newly_observed=["framework_callback"])
        real["results"][0]["topology_coverage"]["observed"] = ["framework_callback"]

        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            reviews=[],
            history=[{
                "round_id": "prior",
                "new_p0_p1_findings": 0,
                "root_cause_families": [],
                "observed_topologies": ["framework_callback"],
            }],
            next_action=rotation_action(),
        )

        self.assertEqual(result["coverage"]["newly_observed"], [])
        self.assertEqual(result["recommended_decision"], "rotate")

    def test_p1_finding_requires_complete_review(self):
        signal = p1_signal()
        finding_id = retro.stable_finding_id(signal)
        result = retro.build_retrospective(
            clean_real_payload(),
            audit_payload(signal),
            reviews=[{"finding_id": finding_id, "root_cause_family": "evidence_identity"}],
            history=[],
        )

        errors = retro.evaluate_retrospective(result)

        self.assertIn(f"finding_review_incomplete:{finding_id}:escape_reason", errors)
        self.assertIn(f"finding_review_incomplete:{finding_id}:regression_test", errors)
        self.assertEqual(result["decision"], "blocked")

    def test_p2_signal_still_requires_explanation_and_optimization(self):
        signal = {
            "signal_type": "capability_gap",
            "severity": "P2",
            "blocking": False,
            "case": "sample",
            "message": "243 APIs remain uncertain",
        }
        finding_id = retro.stable_finding_id(signal)

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), reviews=[], history=[]
        )

        errors = retro.evaluate_retrospective(result)
        self.assertIn(f"finding_review_incomplete:{finding_id}:root_cause_family", errors)
        self.assertIn(f"finding_review_incomplete:{finding_id}:optimization_action", errors)

        reviewed = retro.build_retrospective(
            clean_real_payload(),
            audit_payload(signal),
            reviews=[{
                "finding_id": finding_id,
                "root_cause_family": "static_evidence_limit",
                "escape_reason": "no executable path can prove framework activation",
                "optimization_action": "add runtime activation oracle in the next discovery project",
                "status": "accepted_uncertainty",
            }],
            history=[],
            next_action=rotation_action(),
        )
        self.assertEqual(retro.evaluate_retrospective(reviewed), [])
        self.assertIn(
            "add runtime activation oracle in the next discovery project",
            reviewed["optimization_backlog"],
        )

    def test_p1_case_patch_is_rejected_even_with_regression(self):
        signal = p1_signal()
        finding_id = retro.stable_finding_id(signal)
        review = complete_review(finding_id, resolution_scope="case_patch")

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], history=[]
        )

        self.assertIn(
            f"p0_p1_case_patch_forbidden:{finding_id}",
            retro.evaluate_retrospective(result),
        )

    def test_p1_fixed_review_requires_capability_family_binding(self):
        signal = p1_signal()
        finding_id = retro.stable_finding_id(signal)
        review = complete_review(finding_id, capability_family="")

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], history=[]
        )

        self.assertIn(
            f"finding_review_incomplete:{finding_id}:capability_family",
            retro.evaluate_retrospective(result),
        )

    def test_p1_fixed_review_requires_nonempty_executable_closure_lists(self):
        signal = p1_signal()
        finding_id = retro.stable_finding_id(signal)
        review = complete_review(finding_id, audited_production_paths=[])

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], history=[]
        )

        self.assertIn(
            f"finding_review_incomplete:{finding_id}:audited_production_paths",
            retro.evaluate_retrospective(result),
        )

    def test_repeated_root_cause_requires_architecture_review(self):
        signal = p1_signal("same family, different project")
        finding_id = retro.stable_finding_id(signal)
        review = complete_review(finding_id, architecture_review=False)
        history = [{"round_id": "prior", "root_cause_families": ["evidence_identity"]}]

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], history
        )

        self.assertEqual(result["summary"]["repeated_root_cause_families"], ["evidence_identity"])
        self.assertIn(
            "architecture_review_required:evidence_identity",
            retro.evaluate_retrospective(result),
        )

    def test_repeated_root_cause_requires_architecture_decision(self):
        signal = p1_signal("same family with a nominal architecture review")
        finding_id = retro.stable_finding_id(signal)
        review = complete_review(finding_id, architecture_review=True)
        history = [{"round_id": "prior", "root_cause_families": ["evidence_identity"]}]

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], history
        )

        self.assertIn(
            f"architecture_decision_required:{finding_id}:evidence_identity",
            retro.evaluate_retrospective(result),
        )

    def test_same_round_rerun_is_not_mistaken_for_cross_round_repeat(self):
        signal = p1_signal()
        finding_id = retro.stable_finding_id(signal)
        review = complete_review(finding_id)
        first = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], history=[]
        )
        same_round_history = [{
            "round_id": first["round_id"],
            "new_p0_p1_findings": 1,
            "root_cause_families": ["evidence_identity"],
        }]

        rerun = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], same_round_history
        )

        self.assertEqual(rerun["summary"]["repeated_root_cause_families"], [])
        self.assertNotIn(
            "architecture_review_required:evidence_identity",
            retro.evaluate_retrospective(rerun),
        )

    def test_same_root_cause_twice_in_current_round_requires_architecture_review(self):
        first_signal = p1_signal("first manifestation")
        second_signal = p1_signal("second manifestation")
        reviews = [
            complete_review(retro.stable_finding_id(first_signal)),
            complete_review(retro.stable_finding_id(second_signal)),
        ]

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(first_signal, second_signal), reviews, history=[]
        )

        self.assertEqual(result["summary"]["repeated_root_cause_families"], ["evidence_identity"])
        self.assertIn(
            "architecture_review_required:evidence_identity",
            retro.evaluate_retrospective(result),
        )

    def test_incomplete_oracle_and_performance_block_round(self):
        real = clean_real_payload()
        result = real["results"][0]
        result["edge_truth"]["complete"] = False
        result["performance_envelope"] = {}

        retrospective = retro.build_retrospective(
            real, audit_payload(real=real), [], history=[], next_action=rotation_action()
        )
        errors = retro.evaluate_retrospective(retrospective)

        self.assertIn("oracle_incomplete", errors)
        self.assertIn("performance_evidence_incomplete", errors)
        self.assertEqual(retrospective["decision"], "blocked")

    def test_stale_or_missing_audit_binding_blocks_round(self):
        real = clean_real_payload()
        stale_audit = audit_payload()
        stale_audit["sources"][0]["payload_sha256"] = "0" * 64

        stale = retro.build_retrospective(real, stale_audit, [], history=[])
        missing = retro.build_retrospective(real, {}, [], history=[])

        self.assertIn("audit_input_mismatch", retro.evaluate_retrospective(stale))
        self.assertIn("audit_input_mismatch", retro.evaluate_retrospective(missing))

    def test_over_budget_performance_envelope_is_incomplete(self):
        real = clean_real_payload()
        real["results"][0]["performance_envelope"]["within_budget"] = False

        result = retro.build_retrospective(
            real, audit_payload(real=real), [], history=[]
        )

        self.assertIn(
            "performance_evidence_incomplete", retro.evaluate_retrospective(result)
        )

        missing_budget = clean_real_payload()
        missing_budget["results"][0].pop("performance_budget_seconds")
        result = retro.build_retrospective(
            missing_budget,
            audit_payload(real=missing_budget),
            [],
            history=[],
        )
        self.assertIn(
            "performance_evidence_incomplete", retro.evaluate_retrospective(result)
        )

        missing_typed_verdict = clean_real_payload()
        missing_typed_verdict["results"][0]["performance_envelope"].pop("within_budget")
        result = retro.build_retrospective(
            missing_typed_verdict,
            audit_payload(real=missing_typed_verdict),
            [],
            history=[],
        )
        self.assertIn(
            "performance_evidence_incomplete", retro.evaluate_retrospective(result)
        )

    def test_oracle_cannot_self_certify_with_one_boolean(self):
        real = clean_real_payload()
        result = real["results"][0]
        for field in (
            "api_population", "apis_selected", "apis_accounted", "coverage_ratio",
            "oracle_audit",
        ):
            result.pop(field, None)

        retrospective = retro.build_retrospective(
            real, audit_payload(real=real), [], history=[]
        )

        self.assertIn("oracle_incomplete", retro.evaluate_retrospective(retrospective))

    def test_lowercase_p1_and_invalid_scope_cannot_bypass_review(self):
        signal = p1_signal()
        signal["severity"] = "p1"
        finding_id = retro.stable_finding_id(signal)
        review = complete_review(
            finding_id,
            resolution_scope="none",
            regression_test="not.a.real.Test.test_method",
            architecture_review="false",
        )

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], history=[{
                "round_id": "prior",
                "root_cause_families": ["evidence_identity"],
                "new_p0_p1_findings": 1,
            }]
        )
        errors = retro.evaluate_retrospective(result)

        self.assertIn(f"invalid_resolution_scope:{finding_id}:none", errors)
        self.assertIn(f"regression_test_unresolved:{finding_id}", errors)
        self.assertIn("architecture_review_required:evidence_identity", errors)

    def test_arbitrary_root_cause_family_cannot_evade_cross_round_trend(self):
        signal = p1_signal()
        finding_id = retro.stable_finding_id(signal)
        review = complete_review(finding_id, root_cause_family="one_off_name")

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], history=[]
        )

        self.assertIn(
            f"invalid_root_cause_family:{finding_id}:one_off_name",
            retro.evaluate_retrospective(result),
        )

    def test_rotate_decision_generates_next_project_and_rationale(self):
        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(), [], history=[]
        )

        self.assertEqual(retro.evaluate_retrospective(result), [])
        self.assertEqual(result["next_action"]["decision"], "rotate")
        self.assertEqual(result["next_action"]["project"], "next-orthogonal-real-project")
        self.assertTrue(result["next_action"]["rationale"])

    def test_rotate_rejects_current_project_and_already_covered_topology(self):
        action = rotation_action()
        action["project"] = "sample"
        action["target_topologies"] = ["business_direct"]
        real = clean_real_payload()
        real["results"][0]["topology_coverage"]["observed"] = ["business_direct"]

        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            [],
            history=[{
                "round_id": "prior",
                "new_p0_p1_findings": 0,
                "root_cause_families": [],
                "observed_topologies": ["business_direct"],
            }],
            next_action=action,
        )
        errors = retro.evaluate_retrospective(result)

        self.assertIn("next_action_must_change_project", errors)
        self.assertIn("next_action_has_no_uncovered_topology", errors)

    def test_oracle_identity_anomalies_block_even_when_upstream_blocking_flag_is_false(self):
        for field in (
            "missing_identity_count",
            "duplicate_identity_count",
            "extra_identity_count",
            "invalid_provenance_count",
            "analyzer_extra_identity_count",
            "analyzer_duplicate_identity_count",
            "analyzer_conflict_identity_count",
        ):
            with self.subTest(field=field):
                real = clean_real_payload()
                real["results"][0]["oracle_audit"][field] = 1
                result = retro.build_retrospective(
                    real,
                    audit_payload(real=real),
                    [],
                    history=[],
                    next_action=rotation_action(),
                )

                self.assertFalse(result["evidence"]["oracle_complete"])
                self.assertIn("oracle_incomplete", retro.evaluate_retrospective(result))

    def test_oracle_identity_counters_must_be_present(self):
        real = clean_real_payload()
        del real["results"][0]["oracle_audit"]["analyzer_extra_identity_count"]

        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            [],
            history=[],
            next_action=rotation_action(),
        )

        self.assertFalse(result["evidence"]["oracle_complete"])
        self.assertIn("oracle_incomplete", retro.evaluate_retrospective(result))

    def test_edge_oracle_counters_must_be_present_typed_and_consistent(self):
        mutations = (
            lambda counts: counts.pop("edge_truth_extra_count"),
            lambda counts: counts.__setitem__("oracle_edge_count", "1"),
            lambda counts: counts.__setitem__("edge_reconciliation_row_count", 1),
            lambda counts: counts.__setitem__("edge_truth_correct_count", 1),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                real = clean_real_payload()
                counts = real["results"][0]["edge_truth"]["counts"]
                mutate(counts)
                result = retro.build_retrospective(
                    real,
                    audit_payload(real=real),
                    [],
                    history=[],
                    next_action=rotation_action(),
                )

                self.assertFalse(result["evidence"]["oracle_complete"])
                self.assertIn("oracle_incomplete", retro.evaluate_retrospective(result))

    def test_guard_action_must_target_current_project_and_new_topology(self):
        real = clean_real_payload(newly_observed=["framework_callback"])
        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            [],
            history=[],
            next_action={
                "decision": "guard",
                "project": "different-project",
                "rationale": "stabilize coverage",
                "target_topologies": [],
            },
        )

        errors = retro.evaluate_retrospective(result)
        self.assertIn("next_action_must_keep_current_project", errors)
        self.assertIn("next_action_target_topologies_missing", errors)

    def test_continue_action_must_target_current_project_and_open_high_findings(self):
        finding_id = "external-fixed-p1"
        review = complete_review(
            finding_id,
            severity="P1",
            case="sample",
            message="independent oracle found a false negative",
        )
        result = retro.build_retrospective(
            clean_real_payload(),
            audit_payload(),
            [review],
            history=[],
            next_action={
                "decision": "continue",
                "project": "different-project",
                "rationale": "rerun convergence",
                "target_findings": [],
            },
        )

        errors = retro.evaluate_retrospective(result)
        self.assertIn("next_action_must_keep_current_project", errors)
        self.assertIn("next_action_target_findings_missing", errors)

    def test_continue_action_rejects_unknown_finding_reference(self):
        finding_id = "external-fixed-p1"
        review = complete_review(
            finding_id,
            severity="P1",
            case="sample",
            message="independent oracle found a false negative",
        )
        result = retro.build_retrospective(
            clean_real_payload(),
            audit_payload(),
            [review],
            history=[],
            next_action={
                "decision": "continue",
                "project": "sample",
                "rationale": "rerun convergence",
                "target_findings": [finding_id, "does-not-exist"],
            },
        )

        self.assertIn(
            "next_action_target_findings_mismatch",
            retro.evaluate_retrospective(result),
        )

    def test_blocked_action_cannot_claim_a_different_decision(self):
        real = clean_real_payload()
        real["results"][0]["performance_envelope"]["within_budget"] = False
        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            [],
            history=[],
            next_action={
                "decision": "rotate",
                "project": "another-project",
                "rationale": "ignore the blocker",
                "target_topologies": ["framework_runtime_activation"],
            },
        )

        errors = retro.evaluate_retrospective(result)
        self.assertIn("next_action_decision_mismatch", errors)

    def test_blocked_action_must_reference_exact_domain_errors(self):
        real = clean_real_payload()
        real["results"][0]["performance_envelope"]["within_budget"] = False
        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            [],
            history=[],
            next_action={
                "decision": "blocked",
                "project": "",
                "rationale": "resolve evidence failure",
                "blockers": ["made_up_blocker"],
            },
        )

        self.assertIn("next_action_blockers_mismatch", retro.evaluate_retrospective(result))

    def test_guard_action_cannot_target_topology_from_another_project(self):
        real = clean_real_payload(newly_observed=["project_a_topology"])
        second = dict(real["results"][0])
        second["case"] = "sample-b"
        second["project_root"] = "/tmp/sample-b"
        second["topology_coverage"] = {
            "complete": True,
            "newly_observed": ["project_b_topology"],
            "missing": [],
        }
        real["results"].append(second)
        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            [],
            history=[],
            next_action={
                "decision": "guard",
                "project": "sample",
                "rationale": "stabilize project topology",
                "target_topologies": ["project_b_topology"],
            },
        )

        errors = retro.evaluate_retrospective(result)
        self.assertIn("next_action_guard_targets_not_in_project", errors)
        self.assertIn("next_action_project_scope_incomplete", errors)

    def test_guard_blocks_multiple_projects_even_when_new_topology_names_match(self):
        real = clean_real_payload(newly_observed=["shared_topology"])
        second = dict(real["results"][0])
        second["case"] = "sample-b"
        second["project_root"] = "/tmp/sample-b"
        second["topology_coverage"] = {
            "complete": True,
            "newly_observed": ["shared_topology"],
            "missing": [],
        }
        real["results"].append(second)
        result = retro.build_retrospective(
            real,
            audit_payload(real=real),
            [],
            history=[],
            next_action={
                "decision": "guard",
                "project": "sample",
                "rationale": "stabilize shared topology",
                "target_topologies": ["shared_topology"],
            },
        )

        self.assertIn(
            "next_action_project_scope_incomplete",
            retro.evaluate_retrospective(result),
        )

    def test_audit_requires_complete_status_summary_and_signal_list(self):
        real = clean_real_payload()
        digest_only = {"sources": [{"payload_sha256": retro.payload_sha256(real)}]}

        result = retro.build_retrospective(
            real, digest_only, [], history=[], next_action=rotation_action()
        )

        self.assertIn("audit_input_mismatch", retro.evaluate_retrospective(result))

    def test_audit_summary_counts_must_be_present_integer_fields(self):
        real = clean_real_payload()
        for field, bad_value in (
            ("signal_count", None),
            ("blocking_signals", "0"),
            ("non_blocking_signals", False),
            ("fixture_debt", "0"),
        ):
            with self.subTest(field=field, bad_value=bad_value):
                audit = audit_payload(real=real)
                if bad_value is None:
                    del audit["summary"][field]
                else:
                    audit["summary"][field] = bad_value
                result = retro.build_retrospective(
                    real,
                    audit,
                    [],
                    history=[],
                    next_action=rotation_action(),
                )

                self.assertFalse(result["evidence"]["audit_bound_to_real_input"])
                self.assertIn("audit_input_mismatch", retro.evaluate_retrospective(result))

        for malformed_signal in (
            {"signal_type": "gap", "blocking": False},
            {"signal_type": "gap", "severity": "P2", "blocking": "false"},
        ):
            malformed = audit_payload(malformed_signal, real=real)
            result = retro.build_retrospective(
                real, malformed, [], history=[], next_action=rotation_action()
            )
            self.assertIn("audit_input_mismatch", retro.evaluate_retrospective(result))

        inconsistent = audit_payload({
            "signal_type": "capability_gap",
            "severity": "P2",
            "blocking": True,
            "case": "sample",
            "message": "blocking but summary lies",
        }, real=real)
        inconsistent["summary"]["blocking_signals"] = 0
        result = retro.build_retrospective(
            real, inconsistent, [], history=[], next_action=rotation_action()
        )
        self.assertIn("audit_input_mismatch", retro.evaluate_retrospective(result))

    def test_audit_metadata_does_not_change_round_identity(self):
        real = clean_real_payload()
        first_audit = audit_payload(real=real)
        second_audit = {**first_audit, "generated_at": "2099-01-01T00:00:00Z"}

        first = retro.build_retrospective(
            real, first_audit, [], history=[], next_action=rotation_action()
        )
        second = retro.build_retrospective(
            real, second_audit, [], history=[], next_action=rotation_action()
        )

        self.assertEqual(first["round_id"], second["round_id"])

        nested_metadata = audit_payload(real=real)
        nested_metadata["signals"] = [{
            "signal_type": "capability_gap",
            "severity": "P2",
            "blocking": False,
            "case": "sample",
            "message": "same semantic signal",
        }]
        nested_metadata["summary"].update({
            "signal_count": 1,
            "non_blocking_signals": 1,
        })
        with_timestamp = __import__("copy").deepcopy(nested_metadata)
        with_timestamp["signals"][0]["generated_at"] = "2099-01-01"
        first = retro.build_retrospective(real, nested_metadata, [], history=[])
        second = retro.build_retrospective(real, with_timestamp, [], history=[])
        self.assertEqual(first["round_id"], second["round_id"])

    def test_non_finite_performance_values_are_rejected(self):
        for field, value in (
            ("performance_budget_seconds", "NaN"),
            ("elapsed_seconds", "Infinity"),
        ):
            with self.subTest(field=field):
                real = clean_real_payload()
                if field == "performance_budget_seconds":
                    real["results"][0][field] = value
                else:
                    real["results"][0]["performance_envelope"][field] = value
                result = retro.build_retrospective(
                    real, audit_payload(real=real), [], history=[]
                )
                self.assertIn(
                    "performance_evidence_incomplete",
                    retro.evaluate_retrospective(result),
                )

    def test_string_booleans_cannot_certify_oracle_or_performance(self):
        real = clean_real_payload()
        item = real["results"][0]
        item["complete"] = "false"
        item["topology_coverage"]["complete"] = "false"
        item["performance_envelope"]["within_budget"] = "false"

        result = retro.build_retrospective(
            real, audit_payload(real=real), [], history=[]
        )

        errors = retro.evaluate_retrospective(result)
        self.assertIn("oracle_incomplete", errors)
        self.assertIn("performance_evidence_incomplete", errors)

    def test_retrospective_keeps_oracle_and_performance_facts(self):
        result = retro.build_retrospective(
            clean_real_payload(),
            audit_payload(),
            [],
            history=[],
            next_action=rotation_action(),
        )

        oracle = result["evidence"]["oracle_facts"][0]
        performance = result["evidence"]["performance_facts"][0]
        self.assertEqual(oracle["api_population"], 1)
        self.assertEqual(oracle["api_verified"], 1)
        self.assertEqual(oracle["oracle_edge_count"], 1)
        self.assertEqual(performance["elapsed_seconds"], 12.5)
        self.assertEqual(performance["budget_seconds"], 100.0)
        markdown = retro.render_markdown(result)
        self.assertIn("API Oracle：population=1, verified=1", markdown)
        self.assertIn("性能：elapsed=12.5s, budget=100.0s", markdown)

    def test_top_level_failed_runner_cannot_pass_on_nested_results(self):
        real = clean_real_payload()
        real["status"] = "failed"

        result = retro.build_retrospective(
            real, audit_payload(real=real), [], history=[]
        )

        self.assertIn("real_runner_incomplete", retro.evaluate_retrospective(result))

    def test_rotation_target_must_be_uncovered_across_all_history(self):
        real = clean_real_payload()
        action = rotation_action()
        history = [{
            "round_id": "prior",
            "new_p0_p1_findings": 0,
            "root_cause_families": [],
            "observed_topologies": ["framework_runtime_activation"],
        }]

        result = retro.build_retrospective(
            real, audit_payload(real=real), [], history=history, next_action=action
        )

        self.assertIn(
            "next_action_has_no_uncovered_topology",
            retro.evaluate_retrospective(result),
        )

        action["target_topologies"] = [" framework_runtime_activation "]
        result = retro.build_retrospective(
            real, audit_payload(real=real), [], history=history, next_action=action
        )
        self.assertIn(
            "next_action_has_no_uncovered_topology",
            retro.evaluate_retrospective(result),
        )

    def test_root_cause_whitespace_cannot_bypass_repeat_detection(self):
        signal = p1_signal()
        finding_id = retro.stable_finding_id(signal)
        review = complete_review(
            finding_id,
            root_cause_family=" evidence_identity ",
            architecture_review=False,
        )

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [review], history=[{
                "round_id": "prior",
                "new_p0_p1_findings": 1,
                "root_cause_families": ["evidence_identity"],
            }]
        )

        self.assertEqual(result["summary"]["repeated_root_cause_families"], ["evidence_identity"])
        self.assertIn(
            "architecture_review_required:evidence_identity",
            retro.evaluate_retrospective(result),
        )

    def test_replacing_old_history_round_preserves_chronology(self):
        import json
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "history.json"
            path.write_text(
                json.dumps([{"round_id": "round-a"}, {"round_id": "round-b"}]),
                encoding="utf-8",
            )
            retro._append_history(path.as_posix(), {
                "round_id": "round-a",
                "status": "passed",
                "decision": "guard",
                "summary": {},
                "coverage": {},
            })
            history = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual([item["round_id"] for item in history], ["round-a", "round-b"])

    def test_markdown_reports_counts_and_optimization_actions(self):
        signal = p1_signal()
        finding_id = retro.stable_finding_id(signal)
        result = retro.build_retrospective(
            clean_real_payload(),
            audit_payload(signal),
            [complete_review(finding_id)],
            history=[],
        )

        markdown = retro.render_markdown(result)

        self.assertIn("新增 P0/P1：1", markdown)
        self.assertIn("evidence_identity", markdown)
        self.assertIn("unify evidence identity before graph traversal", markdown)

    def test_accepts_current_real_runner_coverage_shape(self):
        real = clean_real_payload()
        result = real["results"][0]
        result.pop("api_coverage_complete")
        result.update({
            "complete": True,
            "api_population": 252,
            "apis_selected": 252,
            "apis_accounted": 252,
            "coverage_ratio": 1.0,
            "oracle_audit": {
                "selected": 252,
                "verified": 252,
                "incorrect": 0,
                "unverified": 0,
                "oracle_conflicts": 0,
                "missing_identity_count": 0,
                "duplicate_identity_count": 0,
                "extra_identity_count": 0,
                "invalid_provenance_count": 0,
                "analyzer_extra_identity_count": 0,
                "analyzer_duplicate_identity_count": 0,
                "analyzer_conflict_identity_count": 0,
                "blocking": False,
            },
        })

        retrospective = retro.build_retrospective(
            real,
            audit_payload(real=real),
            [],
            history=[],
            next_action=rotation_action(),
        )

        self.assertTrue(retrospective["evidence"]["oracle_complete"])
        self.assertNotIn("oracle_incomplete", retro.evaluate_retrospective(retrospective))

    def test_external_finding_is_not_lost_when_audit_missed_it(self):
        review = complete_review(
            "external-1",
            severity="P1",
            case="sample",
            message="third-party oracle found a false negative",
            status="planned",
        )

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(), [review], history=[]
        )

        self.assertEqual(result["summary"]["new_p0_p1_findings"], 1)
        self.assertEqual(result["findings"][0]["signal_type"], "external_finding")
        self.assertIn("finding_not_closed:external-1", retro.evaluate_retrospective(result))

    def test_round_trend_compares_p0_p1_count_with_previous_round(self):
        signal = p1_signal()
        finding_id = retro.stable_finding_id(signal)
        history = [{
            "round_id": "prior",
            "new_p0_p1_findings": 3,
            "root_cause_families": [],
        }]

        result = retro.build_retrospective(
            clean_real_payload(), audit_payload(signal), [complete_review(finding_id)], history
        )

        self.assertEqual(result["trend"]["previous_p0_p1_findings"], 3)
        self.assertEqual(result["trend"]["p0_p1_delta"], -2)
        self.assertEqual(result["trend"]["direction"], "decreasing")


if __name__ == "__main__":
    unittest.main()
