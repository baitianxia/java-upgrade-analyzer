#!/usr/bin/env python3
"""Build and gate the retrospective for one real-project test round."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import unittest


REQUIRED_REVIEW_FIELDS = (
    "root_cause_family",
    "escape_reason",
    "optimization_action",
    "status",
)
HIGH_SEVERITY_REVIEW_FIELDS = ("resolution_scope", "regression_test")
CAPABILITY_BINDING_STRING_FIELDS = ("capability_family", "invariant_id")
CAPABILITY_BINDING_LIST_FIELDS = (
    "audited_production_paths",
    "generalized_regression_tests",
    "negative_regression_tests",
    "mutation_tests",
    "cross_project_guards",
)
HIGH_SEVERITIES = {"P0", "P1", "high"}
ALLOWED_RESOLUTION_SCOPES = {"architecture", "evidence_model", "generic_logic"}
ALLOWED_ROOT_CAUSE_FAMILIES = {
    "artifact_provenance",
    "business_activation_not_proven",
    "coverage_scope",
    "error_visibility",
    "evidence_identity",
    "framework_semantics",
    "new_architecture_gap",
    "oracle_gap",
    "output_contract",
    "ownership_classification",
    "performance_complexity",
    "static_evidence_limit",
    "test_asset_invalid",
    "workflow_gate",
}


def _canonical_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def payload_sha256(payload: dict) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _normalized_severity(value) -> str:
    severity = str(value or "").strip().upper()
    return "P1" if severity == "HIGH" else severity


def _resolves_to_unittest(reference: str) -> bool:
    if not reference or not reference.startswith("tests."):
        return False
    try:
        suite = unittest.defaultTestLoader.loadTestsFromName(reference)
    except (AttributeError, ImportError, TypeError, ValueError):
        return False
    def contains_failed_test(node) -> bool:
        if isinstance(node, unittest.TestSuite):
            return any(contains_failed_test(child) for child in node)
        return type(node).__name__ == "_FailedTest"

    return suite.countTestCases() > 0 and not contains_failed_test(suite)


def stable_finding_id(signal: dict) -> str:
    identity = {
        "case": str(signal.get("case") or ""),
        "signal_type": str(signal.get("signal_type") or signal.get("kind") or ""),
        "step": str(signal.get("step") or ""),
        "symbol": str(signal.get("symbol") or ""),
        "reason_code": str(signal.get("reason_code") or ""),
        "message": str(signal.get("message") or ""),
    }
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()[:16]
    return f"finding-{digest}"


def _results(real_payload: dict) -> list[dict]:
    results = real_payload.get("results")
    if not isinstance(results, list):
        return []
    if not all(isinstance(result, dict) for result in results):
        raise ValueError("real-project results must contain JSON objects")
    return list(results)


def _oracle_complete(results: list[dict]) -> bool:
    if not results:
        return False
    for result in results:
        if result.get("status") != "passed":
            return False
        population = int(result.get("api_population") or 0)
        coverage_complete = bool(
            result.get("complete") is True
            and population > 0
            and int(result.get("apis_selected") or 0) == population
            and int(result.get("apis_accounted") or 0) == population
            and float(result.get("coverage_ratio") or 0.0) == 1.0
        )
        if not coverage_complete:
            return False
        audit = result.get("result_audit") or {}
        if not audit or audit.get("failures") or int(audit.get("unverified") or 0):
            return False
        oracle_audit = result.get("oracle_audit") or {}
        zero_count_fields = (
            "incorrect",
            "unverified",
            "oracle_conflicts",
            "missing_identity_count",
            "duplicate_identity_count",
            "extra_identity_count",
            "invalid_provenance_count",
            "analyzer_extra_identity_count",
            "analyzer_duplicate_identity_count",
            "analyzer_conflict_identity_count",
        )
        if not oracle_audit or (
            oracle_audit.get("blocking") is not False
            or type(oracle_audit.get("selected")) is not int
            or oracle_audit.get("selected") != population
            or type(oracle_audit.get("verified")) is not int
            or oracle_audit.get("verified") != population
            or any(
                type(oracle_audit.get(field)) is not int
                or oracle_audit.get(field) != 0
                for field in zero_count_fields
            )
        ):
            return False
        edge_truth = result.get("edge_truth") or {}
        counts = edge_truth.get("counts") or {}
        positive_edge_fields = (
            "oracle_edge_count",
            "analyzer_edge_count",
            "edge_reconciliation_row_count",
            "edge_truth_correct_count",
        )
        zero_edge_fields = (
            "edge_truth_missing_count",
            "edge_truth_extra_count",
            "edge_truth_identity_mismatch_count",
            "edge_truth_provenance_invalid_count",
            "edge_truth_oracle_conflict_count",
        )
        if (
            edge_truth.get("complete") is not True
            or edge_truth.get("blocking") is not False
            or edge_truth.get("errors")
            or not counts
            or any(
                type(counts.get(field)) is not int or counts.get(field) <= 0
                for field in positive_edge_fields
            )
            or any(
                type(counts.get(field)) is not int or counts.get(field) != 0
                for field in zero_edge_fields
            )
            or counts.get("edge_reconciliation_row_count")
            != counts.get("oracle_edge_count", 0) + counts.get("analyzer_edge_count", 0)
            or counts.get("edge_truth_correct_count")
            != counts.get("edge_reconciliation_row_count")
        ):
            return False
        topology = result.get("topology_coverage") or {}
        if topology.get("complete") is not True:
            return False
    return True


def _performance_complete(results: list[dict], signals: list[dict]) -> bool:
    if not results:
        return False
    if any(str(signal.get("signal_type") or "") == "performance_regression" for signal in signals):
        return False
    for result in results:
        envelope = result.get("performance_envelope") or {}
        if not envelope or envelope.get("within_budget") is not True:
            return False
        budget = float(result.get("performance_budget_seconds") or 0.0)
        elapsed = float(envelope.get("elapsed_seconds") or result.get("elapsed_seconds") or 0.0)
        if (
            not math.isfinite(budget)
            or not math.isfinite(elapsed)
            or budget <= 0.0
            or elapsed <= 0.0
            or elapsed > budget
        ):
            return False
        if (
            envelope.get("oracle_timed_out") is not False
            or envelope.get("oracle_interrupted") is not False
            or "oracle_parse_failure_count" not in envelope
            or int(envelope.get("oracle_parse_failure_count") or 0)
        ):
            return False
    return True


def _project_provenance_complete(results: list[dict]) -> bool:
    if not results:
        return False
    for result in results:
        health = result.get("project_asset_health") or {}
        revision = str(health.get("git_revision") or "")
        if len(revision) != 40 or any(char not in "0123456789abcdefABCDEF" for char in revision):
            return False
        if health.get("git_dirty") is not False:
            return False
    return True


def _real_runner_complete(real_payload: dict, results: list[dict]) -> bool:
    return bool(
        real_payload.get("status") == "passed"
        and results
        and all(result.get("status") == "passed" for result in results)
    )


def _audit_bound_to_real_payload(real_payload: dict, audit_payload: dict) -> bool:
    sources = audit_payload.get("sources") or []
    summary = audit_payload.get("summary")
    signals = audit_payload.get("signals")
    signals_valid = isinstance(signals, list) and all(
        isinstance(signal, dict)
        and _normalized_severity(signal.get("severity")) in {"P0", "P1", "P2", "P3"}
        and type(signal.get("blocking")) is bool
        for signal in signals
    )
    computed_blocking = (
        sum(bool(signal.get("blocking")) for signal in signals)
        if signals_valid else -1
    )
    computed_fixture_debt = (
        sum(
            bool(signal.get("blocking"))
            and str(signal.get("fixture_status") or "") in {"", "missing"}
            for signal in signals
        )
        if signals_valid else -1
    )
    summary_count_fields = (
        "signal_count",
        "blocking_signals",
        "non_blocking_signals",
        "fixture_debt",
    )
    summary_counts_valid = isinstance(summary, dict) and all(
        type(summary.get(field)) is int for field in summary_count_fields
    )
    status = audit_payload.get("status")
    return bool(
        status in {"clean", "signals_found"}
        and isinstance(summary, dict)
        and summary_counts_valid
        and signals_valid
        and status == ("signals_found" if signals else "clean")
        and summary.get("signal_count") == len(signals)
        and summary.get("blocking_signals") == computed_blocking
        and summary.get("non_blocking_signals") == len(signals) - computed_blocking
        and summary.get("fixture_debt") == computed_fixture_debt
        and len(sources) == 1
        and str(sources[0].get("payload_sha256") or "") == payload_sha256(real_payload)
    )


def _oracle_facts(results: list[dict]) -> list[dict]:
    facts = []
    for result in results:
        oracle = result.get("oracle_audit") or {}
        edge_counts = (result.get("edge_truth") or {}).get("counts") or {}
        facts.append({
            "case": str(result.get("case") or ""),
            "api_population": int(result.get("api_population") or 0),
            "api_selected": int(result.get("apis_selected") or 0),
            "api_accounted": int(result.get("apis_accounted") or 0),
            "api_verified": int(oracle.get("verified") or 0),
            "api_incorrect": int(oracle.get("incorrect") or 0),
            "api_unverified": int(oracle.get("unverified") or 0),
            "oracle_conflicts": int(oracle.get("oracle_conflicts") or 0),
            "api_missing_identities": int(oracle.get("missing_identity_count") or 0),
            "api_duplicate_identities": int(oracle.get("duplicate_identity_count") or 0),
            "api_extra_oracle_identities": int(oracle.get("extra_identity_count") or 0),
            "api_invalid_provenance": int(oracle.get("invalid_provenance_count") or 0),
            "api_extra_analyzer_identities": int(
                oracle.get("analyzer_extra_identity_count") or 0
            ),
            "api_duplicate_analyzer_identities": int(
                oracle.get("analyzer_duplicate_identity_count") or 0
            ),
            "api_conflicting_analyzer_identities": int(
                oracle.get("analyzer_conflict_identity_count") or 0
            ),
            "oracle_edge_count": int(edge_counts.get("oracle_edge_count") or 0),
            "analyzer_edge_count": int(edge_counts.get("analyzer_edge_count") or 0),
            "edge_missing": int(edge_counts.get("edge_truth_missing_count") or 0),
            "edge_extra": int(edge_counts.get("edge_truth_extra_count") or 0),
            "edge_identity_mismatch": int(
                edge_counts.get("edge_truth_identity_mismatch_count") or 0
            ),
            "edge_provenance_invalid": int(
                edge_counts.get("edge_truth_provenance_invalid_count") or 0
            ),
        })
    return facts


def _performance_facts(results: list[dict]) -> list[dict]:
    facts = []
    for result in results:
        envelope = result.get("performance_envelope") or {}
        facts.append({
            "case": str(result.get("case") or ""),
            "elapsed_seconds": float(
                envelope.get("elapsed_seconds") or result.get("elapsed_seconds") or 0.0
            ),
            "budget_seconds": float(result.get("performance_budget_seconds") or 0.0),
            "oracle_elapsed_seconds": float(envelope.get("oracle_elapsed_seconds") or 0.0),
            "oracle_parse_failure_count": int(
                envelope.get("oracle_parse_failure_count") or 0
            ),
            "oracle_timed_out": envelope.get("oracle_timed_out"),
            "oracle_interrupted": envelope.get("oracle_interrupted"),
            "potential_pairs_per_api": float(
                envelope.get("potential_pairs_per_api") or 0.0
            ),
        })
    return facts


def _history_families(history: list[dict]) -> set[str]:
    return {
        str(family).strip()
        for round_item in history
        for family in (round_item.get("root_cause_families") or [])
        if str(family).strip()
    }


def _base_errors(payload: dict, *, include_next_action: bool = True) -> list[str]:
    errors: list[str] = [str(error) for error in (payload.get("input_errors") or [])]
    evidence = payload.get("evidence") or {}
    if not evidence.get("oracle_complete"):
        errors.append("oracle_incomplete")
    if not evidence.get("performance_complete"):
        errors.append("performance_evidence_incomplete")
    if not evidence.get("project_provenance_complete"):
        errors.append("project_provenance_incomplete")
    if not evidence.get("audit_bound_to_real_input"):
        errors.append("audit_input_mismatch")
    if not evidence.get("real_runner_complete"):
        errors.append("real_runner_incomplete")
    fixture_debt = int(evidence.get("fixture_debt") or 0)
    if fixture_debt:
        errors.append(f"fixture_debt_open:{fixture_debt}")

    blocking = int((payload.get("summary") or {}).get("blocking_quality_signals") or 0)
    if blocking:
        errors.append(f"blocking_quality_signals:{blocking}")

    for finding in payload.get("findings") or []:
        finding_id = str(finding.get("finding_id") or "")
        review = finding.get("review") or {}
        severity = _normalized_severity(finding.get("severity"))
        required_fields = REQUIRED_REVIEW_FIELDS
        if severity in HIGH_SEVERITIES:
            required_fields += HIGH_SEVERITY_REVIEW_FIELDS
        for field in required_fields:
            if not str(review.get(field) or "").strip():
                errors.append(f"finding_review_incomplete:{finding_id}:{field}")
        if severity in HIGH_SEVERITIES and str(review.get("status") or "") == "fixed":
            for field in CAPABILITY_BINDING_STRING_FIELDS:
                if not str(review.get(field) or "").strip():
                    errors.append(f"finding_review_incomplete:{finding_id}:{field}")
            for field in CAPABILITY_BINDING_LIST_FIELDS:
                value = review.get(field)
                if (
                    not isinstance(value, list)
                    or not value
                    or not all(isinstance(item, str) and item.strip() for item in value)
                ):
                    errors.append(f"finding_review_incomplete:{finding_id}:{field}")
        root_cause_family = str(review.get("root_cause_family") or "").strip()
        if root_cause_family and root_cause_family not in ALLOWED_ROOT_CAUSE_FAMILIES:
            errors.append(f"invalid_root_cause_family:{finding_id}:{root_cause_family}")
        if (
            root_cause_family == "new_architecture_gap"
            and not str(review.get("root_cause_definition") or "").strip()
        ):
            errors.append(f"new_root_cause_definition_missing:{finding_id}")
        if severity in HIGH_SEVERITIES:
            resolution_scope = str(review.get("resolution_scope") or "").strip()
            if resolution_scope == "case_patch":
                errors.append(f"p0_p1_case_patch_forbidden:{finding_id}")
            elif resolution_scope and resolution_scope not in ALLOWED_RESOLUTION_SCOPES:
                errors.append(f"invalid_resolution_scope:{finding_id}:{resolution_scope}")
            if not _resolves_to_unittest(str(review.get("regression_test") or "")):
                errors.append(f"regression_test_unresolved:{finding_id}")
            if str(review.get("status") or "") != "fixed":
                errors.append(f"finding_not_closed:{finding_id}")

    repeated = set((payload.get("summary") or {}).get("repeated_root_cause_families") or [])
    for family in sorted(repeated):
        family_reviews = [
            (finding.get("review") or {})
            for finding in payload.get("findings") or []
            if str(
                (finding.get("review") or {}).get("root_cause_family") or ""
            ).strip() == family
        ]
        if not family_reviews or not all(review.get("architecture_review") is True for review in family_reviews):
            errors.append(f"architecture_review_required:{family}")
        for finding in payload.get("findings") or []:
            review = finding.get("review") or {}
            if str(review.get("root_cause_family") or "").strip() != family:
                continue
            if not str(review.get("architecture_decision") or "").strip():
                finding_id = str(finding.get("finding_id") or "")
                errors.append(
                    f"architecture_decision_required:{finding_id}:{family}"
                )

    recommended = str(payload.get("recommended_decision") or "")
    next_action = payload.get("next_action") or {}
    if include_next_action:
        domain_errors = list(dict.fromkeys(errors))
        if str(next_action.get("decision") or "") != recommended:
            errors.append("next_action_decision_mismatch")
        if recommended != "blocked" and not str(next_action.get("project") or "").strip():
            errors.append("next_action_project_missing")
        if not str(next_action.get("rationale") or "").strip():
            errors.append("next_action_rationale_missing")
        project = str(next_action.get("project") or "").strip()
        current_projects = {
            str(value or "").strip()
            for case in (payload.get("cases") or [])
            for value in (case.get("case"), case.get("project_root"))
            if str(value or "").strip()
        }
        if recommended in {"guard", "continue"} and project not in current_projects:
            errors.append("next_action_must_keep_current_project")
        if recommended == "guard":
            raw_targets = next_action.get("target_topologies")
            if not isinstance(raw_targets, list) or not raw_targets or not all(
                isinstance(item, str) and item.strip() for item in (raw_targets or [])
            ):
                errors.append("next_action_target_topologies_missing")
            else:
                targets = {item.strip() for item in raw_targets}
                newly_observed = {
                    str(item).strip()
                    for item in ((payload.get("coverage") or {}).get("newly_observed") or [])
                    if str(item).strip()
                }
                if not targets.issubset(newly_observed):
                    errors.append("next_action_guard_targets_not_new")
                selected_case = next((
                    case for case in (payload.get("cases") or [])
                    if project in {
                        str(case.get("case") or "").strip(),
                        str(case.get("project_root") or "").strip(),
                    }
                ), {})
                project_new = {
                    str(item).strip()
                    for item in (selected_case.get("newly_observed_topologies") or [])
                    if str(item).strip()
                }
                if not targets.issubset(project_new):
                    errors.append("next_action_guard_targets_not_in_project")
                if targets != project_new:
                    errors.append("next_action_guard_targets_mismatch")
                if project_new != newly_observed:
                    errors.append("next_action_project_scope_incomplete")
                affected_cases = [
                    case for case in (payload.get("cases") or [])
                    if case.get("newly_observed_topologies")
                ]
                if len(affected_cases) > 1:
                    errors.append("next_action_project_scope_incomplete")
        elif recommended == "continue":
            raw_findings = next_action.get("target_findings")
            high_findings = {
                str(finding.get("finding_id") or "")
                for finding in (payload.get("findings") or [])
                if _normalized_severity(finding.get("severity")) in HIGH_SEVERITIES
            }
            valid_findings = bool(
                isinstance(raw_findings, list) and raw_findings and all(
                isinstance(item, str) and item.strip() for item in (raw_findings or [])
                )
            )
            targets = {item.strip() for item in (raw_findings or [])} if valid_findings else set()
            if not valid_findings or not high_findings.issubset(targets):
                errors.append("next_action_target_findings_missing")
            if valid_findings and targets != high_findings:
                errors.append("next_action_target_findings_mismatch")
            selected_case_name = next((
                str(case.get("case") or "")
                for case in (payload.get("cases") or [])
                if project in {
                    str(case.get("case") or "").strip(),
                    str(case.get("project_root") or "").strip(),
                }
            ), "")
            project_findings = {
                str(finding.get("finding_id") or "")
                for finding in (payload.get("findings") or [])
                if _normalized_severity(finding.get("severity")) in HIGH_SEVERITIES
                and str(finding.get("case") or "") == selected_case_name
            }
            if targets and not targets.issubset(project_findings):
                errors.append("next_action_findings_not_in_project")
            if project_findings != high_findings:
                errors.append("next_action_project_scope_incomplete")
        elif recommended == "blocked":
            blockers = next_action.get("blockers")
            if not isinstance(blockers, list) or not blockers or not all(
                isinstance(item, str) and item.strip() for item in (blockers or [])
            ):
                errors.append("next_action_blockers_missing")
            elif (
                len(blockers) != len(set(blockers))
                or set(blockers) != set(domain_errors)
            ):
                errors.append("next_action_blockers_mismatch")
        elif recommended == "rotate":
            if project and project in current_projects:
                errors.append("next_action_must_change_project")
            raw_targets = next_action.get("target_topologies")
            if not isinstance(raw_targets, list) or not raw_targets or not all(
                isinstance(item, str) and item.strip() for item in (raw_targets or [])
            ):
                errors.append("next_action_target_topologies_missing")
            else:
                normalized_targets = {item.strip() for item in raw_targets}
                coverage = payload.get("coverage") or {}
                observed = {
                    str(item).strip()
                    for item in (
                        list(coverage.get("observed") or [])
                        + list(coverage.get("historically_observed") or [])
                    )
                }
                if not (normalized_targets - observed):
                    errors.append("next_action_has_no_uncovered_topology")
    return list(dict.fromkeys(errors))


def evaluate_retrospective(payload: dict) -> list[str]:
    return _base_errors(payload)


def build_retrospective(
    real_payload: dict,
    audit_payload: dict,
    reviews: list[dict],
    history: list[dict],
    next_action: dict | None = None,
    input_errors: list[str] | None = None,
) -> dict:
    results = _results(real_payload)
    signals = list(audit_payload.get("signals") or [])
    if not all(isinstance(signal, dict) for signal in signals):
        raise ValueError("audit signals must contain JSON objects")
    audit_identity = {
        "status": audit_payload.get("status"),
        "signals": [
            {
                "finding_id": stable_finding_id(signal),
                "severity": _normalized_severity(signal.get("severity")),
                "blocking": bool(signal.get("blocking")),
                "fixture_status": str(signal.get("fixture_status") or ""),
                "count": int(signal.get("count") or 0),
            }
            for signal in signals
        ],
        "source_payload_sha256": [
            str(source.get("payload_sha256") or "")
            for source in (audit_payload.get("sources") or [])
        ],
    }
    round_identity = {
        "cases": [str(result.get("case") or "") for result in results],
        "results": real_payload,
        "audit": audit_identity,
    }
    round_id = "round-" + hashlib.sha256(
        _canonical_json(round_identity).encode("utf-8")
    ).hexdigest()[:16]
    review_by_id = {
        str(review.get("finding_id") or ""): dict(review)
        for review in reviews
        if str(review.get("finding_id") or "")
    }
    findings = []
    for signal in signals:
        finding_id = stable_finding_id(signal)
        findings.append({
            "finding_id": finding_id,
            "case": str(signal.get("case") or ""),
            "signal_type": str(signal.get("signal_type") or signal.get("kind") or ""),
            "severity": _normalized_severity(signal.get("severity")),
            "blocking": bool(signal.get("blocking")),
            "message": str(signal.get("message") or ""),
            "review": review_by_id.get(finding_id, {}),
        })
    known_finding_ids = {finding["finding_id"] for finding in findings}
    for review in reviews:
        finding_id = str(review.get("finding_id") or "")
        if not finding_id or finding_id in known_finding_ids:
            continue
        findings.append({
            "finding_id": finding_id,
            "case": str(review.get("case") or ""),
            "signal_type": "external_finding",
            "severity": _normalized_severity(review.get("severity") or "P1"),
            "blocking": str(review.get("status") or "") != "fixed",
            "message": str(review.get("message") or "external finding"),
            "review": dict(review),
        })

    family_counts = Counter(
        str((finding.get("review") or {}).get("root_cause_family") or "").strip()
        for finding in findings
        if str((finding.get("review") or {}).get("root_cause_family") or "").strip()
    )
    root_cause_families = sorted(family_counts)
    matching_history_index = next(
        (index for index, item in enumerate(history) if item.get("round_id") == round_id),
        None,
    )
    if matching_history_index is None:
        prior_history = history
        previous_round = history[-1] if history else None
    else:
        prior_history = history[:matching_history_index]
        previous_round = history[matching_history_index - 1] if matching_history_index else None
    repeated = sorted(
        (set(root_cause_families) & _history_families(prior_history))
        | {family for family, count in family_counts.items() if count > 1}
    )
    observed_topologies = sorted({
        str(topology)
        for result in results
        for topology in (
            (result.get("topology_coverage") or {}).get("observed")
            or (result.get("topology_coverage") or {}).get("newly_observed")
            or []
        )
        if str(topology)
    })
    prior_observed_topologies = {
        str(topology)
        for item in prior_history
        for topology in (
            item.get("observed_topologies")
            or item.get("newly_observed_topologies")
            or []
        )
        if str(topology)
    }
    newly_observed = sorted(set(observed_topologies) - prior_observed_topologies)
    missing_topologies = sorted({
        str(topology)
        for result in results
        for topology in ((result.get("topology_coverage") or {}).get("missing") or [])
        if str(topology)
    })
    audit_summary = audit_payload.get("summary") or {}
    p0_p1 = sum(
        1 for finding in findings
        if _normalized_severity(finding["severity"]) in HIGH_SEVERITIES
    )
    previous_p0_p1 = (
        int(previous_round.get("new_p0_p1_findings") or 0)
        if previous_round is not None else None
    )
    p0_p1_delta = None if previous_p0_p1 is None else p0_p1 - previous_p0_p1
    if p0_p1_delta is None:
        trend_direction = "no_baseline"
    elif p0_p1_delta < 0:
        trend_direction = "decreasing"
    elif p0_p1_delta > 0:
        trend_direction = "increasing"
    else:
        trend_direction = "flat"
    optimization_backlog = sorted({
        str((finding.get("review") or {}).get("optimization_action") or "")
        for finding in findings
        if str((finding.get("review") or {}).get("optimization_action") or "")
    } | {f"cover_topology:{topology}" for topology in missing_topologies})
    payload = {
        "round_id": round_id,
        "status": "pending_evaluation",
        "decision": "pending_evaluation",
        "cases": [
            {
                "case": str(result.get("case") or ""),
                "status": str(result.get("status") or ""),
                "project_root": str(result.get("project_root") or ""),
                "git_revision": str(
                    (result.get("project_asset_health") or {}).get("git_revision") or ""
                ),
                "git_dirty": (result.get("project_asset_health") or {}).get("git_dirty"),
                "newly_observed_topologies": sorted({
                    str(item).strip()
                    for item in (
                        (result.get("topology_coverage") or {}).get("observed")
                        or (result.get("topology_coverage") or {}).get("newly_observed")
                        or []
                    )
                    if str(item).strip()
                } - prior_observed_topologies),
            }
            for result in results
        ],
        "summary": {
            "case_count": len(results),
            "finding_count": len(findings),
            "new_p0_p1_findings": p0_p1,
            "blocking_quality_signals": int(audit_summary.get("blocking_signals") or 0),
            "root_cause_families": root_cause_families,
            "repeated_root_cause_families": repeated,
        },
        "coverage": {
            "observed": observed_topologies,
            "historically_observed": sorted(prior_observed_topologies),
            "newly_observed": newly_observed,
            "missing": missing_topologies,
        },
        "trend": {
            "previous_p0_p1_findings": previous_p0_p1,
            "p0_p1_delta": p0_p1_delta,
            "direction": trend_direction,
        },
        "optimization_backlog": optimization_backlog,
        "input_errors": list(input_errors or []),
        "evidence": {
            "oracle_complete": _oracle_complete(results),
            "performance_complete": _performance_complete(results, signals),
            "project_provenance_complete": _project_provenance_complete(results),
            "real_runner_complete": _real_runner_complete(real_payload, results),
            "audit_bound_to_real_input": _audit_bound_to_real_payload(
                real_payload, audit_payload
            ),
            "fixture_debt": int(audit_summary.get("fixture_debt") or 0),
            "oracle_facts": _oracle_facts(results),
            "performance_facts": _performance_facts(results),
        },
        "findings": findings,
    }
    domain_errors = _base_errors(payload, include_next_action=False)
    if domain_errors:
        recommended_decision = "blocked"
    elif p0_p1:
        recommended_decision = "continue"
    elif newly_observed:
        recommended_decision = "guard"
    else:
        recommended_decision = "rotate"
    if next_action is None and recommended_decision == "guard":
        next_action = {
            "decision": "guard",
            "project": str((payload.get("cases") or [{}])[0].get("case") or ""),
            "rationale": "new topology coverage must be stabilized as a guard before rotation",
            "target_topologies": newly_observed,
        }
    elif next_action is None and recommended_decision == "continue":
        next_action = {
            "decision": "continue",
            "project": str((payload.get("cases") or [{}])[0].get("case") or ""),
            "rationale": "reviewed P0/P1 findings require another convergence run",
            "target_findings": [
                finding["finding_id"] for finding in findings
                if _normalized_severity(finding.get("severity")) in HIGH_SEVERITIES
            ],
        }
    elif next_action is None and recommended_decision == "blocked":
        next_action = {
            "decision": "blocked",
            "project": "",
            "rationale": "; ".join(domain_errors),
            "target_topologies": missing_topologies,
            "blockers": domain_errors,
        }
    payload["recommended_decision"] = recommended_decision
    payload["next_action"] = dict(next_action or {})
    errors = _base_errors(payload)
    payload["errors"] = errors
    if errors:
        payload["status"] = "failed"
        payload["decision"] = "blocked"
    else:
        payload["status"] = "passed"
        payload["decision"] = recommended_decision
    return payload


def render_markdown(payload: dict) -> str:
    summary = payload.get("summary") or {}
    evidence = payload.get("evidence") or {}
    coverage = payload.get("coverage") or {}
    trend = payload.get("trend") or {}
    next_action = payload.get("next_action") or {}
    lines = [
        "# 测试轮次复盘",
        "",
        f"- 轮次：`{payload.get('round_id', '')}`",
        f"- 状态：`{payload.get('status', '')}`",
        f"- 下一步：`{payload.get('decision', '')}`",
        f"- 项目数：{summary.get('case_count', 0)}",
        f"- 新增 P0/P1：{summary.get('new_p0_p1_findings', 0)}",
        f"- Oracle 完整：{str(bool(evidence.get('oracle_complete'))).lower()}",
        f"- 性能证据完整：{str(bool(evidence.get('performance_complete'))).lower()}",
        f"- 项目来源完整：{str(bool(evidence.get('project_provenance_complete'))).lower()}",
        f"- Fixture debt：{evidence.get('fixture_debt', 0)}",
        f"- 缺陷趋势：{trend.get('direction', 'no_baseline')} "
        f"(delta={trend.get('p0_p1_delta')})",
        f"- 下一项目：{next_action.get('project') or '未指定'}",
        f"- 决策依据：{next_action.get('rationale') or '未填写'}",
        "",
        "## Oracle 与性能事实",
        "",
    ]
    oracle_by_case = {
        fact.get("case"): fact for fact in (evidence.get("oracle_facts") or [])
    }
    performance_by_case = {
        fact.get("case"): fact for fact in (evidence.get("performance_facts") or [])
    }
    for case in payload.get("cases") or []:
        case_name = case.get("case")
        oracle = oracle_by_case.get(case_name) or {}
        performance = performance_by_case.get(case_name) or {}
        lines.extend([
            f"### {case_name}",
            "",
            "- API Oracle：population={api_population}, verified={api_verified}, "
            "incorrect={api_incorrect}, unverified={api_unverified}".format(**oracle),
            "- Edge Oracle：oracle={oracle_edge_count}, analyzer={analyzer_edge_count}, "
            "missing={edge_missing}, extra={edge_extra}, identity_mismatch={edge_identity_mismatch}".format(
                **oracle
            ),
            "- 性能：elapsed={elapsed_seconds}s, budget={budget_seconds}s, "
            "oracle_elapsed={oracle_elapsed_seconds}s, parse_failures={oracle_parse_failure_count}".format(
                **performance
            ),
            "",
        ])
    lines.extend([
        "## 覆盖变化",
        "",
        f"- 新增拓扑：{', '.join(coverage.get('newly_observed') or []) or '无'}",
        f"- 缺失拓扑：{', '.join(coverage.get('missing') or []) or '无'}",
        "",
        "## 待优化点",
        "",
    ])
    backlog = payload.get("optimization_backlog") or []
    lines.extend(f"- {item}" for item in backlog)
    if not backlog:
        lines.append("- 无")
    lines.extend([
        "",
        "## Findings",
        "",
    ])
    if not payload.get("findings"):
        lines.append("本轮没有质量 finding。")
    for finding in payload.get("findings") or []:
        review = finding.get("review") or {}
        lines.extend([
            f"### {finding.get('finding_id')} ({finding.get('severity')})",
            "",
            f"- 根因族：{review.get('root_cause_family') or '未填写'}",
            f"- 逃逸原因：{review.get('escape_reason') or '未填写'}",
            f"- 修复范围：{review.get('resolution_scope') or '未填写'}",
            f"- 回归测试：{review.get('regression_test') or '未填写'}",
            f"- 优化动作：{review.get('optimization_action') or '未填写'}",
            "",
        ])
    if payload.get("errors"):
        lines.extend(["## 阻塞项", ""])
        lines.extend(f"- `{error}`" for error in payload["errors"])
    return "\n".join(lines).rstrip() + "\n"


def _load_json(path: str, default):
    if not path:
        return default
    source = Path(path)
    if not source.exists():
        return default
    return json.loads(source.read_text(encoding="utf-8"))


def _load_required_json(path: str) -> dict:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(f"required retrospective input missing: {source}")
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"required retrospective input must be a JSON object: {source}")
    return payload


def _write(path: str, text: str) -> None:
    if not path:
        return
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")


def _append_history(path: str, payload: dict, existing_history: list[dict] | None = None) -> None:
    if not path:
        return
    history = list(existing_history) if existing_history is not None else _load_json(path, [])
    if not isinstance(history, list):
        raise ValueError("retrospective history must be a JSON array")
    entry = {
        "round_id": payload["round_id"],
        "status": payload["status"],
        "decision": payload["decision"],
        "root_cause_families": (payload.get("summary") or {}).get("root_cause_families") or [],
        "new_p0_p1_findings": int((payload.get("summary") or {}).get("new_p0_p1_findings") or 0),
        "newly_observed_topologies": (payload.get("coverage") or {}).get("newly_observed") or [],
        "observed_topologies": (payload.get("coverage") or {}).get("observed") or [],
    }
    existing_index = next(
        (index for index, item in enumerate(history) if item.get("round_id") == payload["round_id"]),
        None,
    )
    if existing_index is None:
        history.append(entry)
    else:
        history[existing_index] = entry
    _write(path, json.dumps(history, ensure_ascii=False, indent=2) + "\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Gate one real-project test round retrospective")
    parser.add_argument("real_json")
    parser.add_argument("audit_json")
    parser.add_argument("--reviews", default="")
    parser.add_argument("--history", default="")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--markdown-out", default="")
    args = parser.parse_args(argv)

    input_errors = []
    try:
        real_payload = _load_required_json(args.real_json)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        real_payload = {}
        input_errors.append(f"real_input_error:{type(error).__name__}:{error}")
    try:
        audit_payload = _load_required_json(args.audit_json)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        audit_payload = {}
        input_errors.append(f"audit_input_error:{type(error).__name__}:{error}")
    try:
        history = _load_json(args.history, [])
        if not isinstance(history, list):
            raise ValueError("retrospective history must be a JSON array")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        history = []
        input_errors.append(f"history_input_error:{type(error).__name__}:{error}")
    try:
        review_payload = _load_json(args.reviews, [])
    except (OSError, ValueError, json.JSONDecodeError) as error:
        review_payload = []
        input_errors.append(f"reviews_input_error:{type(error).__name__}:{error}")
    if isinstance(review_payload, dict):
        reviews = list(review_payload.get("findings") or [])
        next_action = review_payload.get("next_action") or None
    elif isinstance(review_payload, list):
        reviews = review_payload
        next_action = None
    else:
        reviews = []
        next_action = None
        input_errors.append("reviews_input_error:ValueError:reviews must be a JSON array or object")
    try:
        payload = build_retrospective(
            real_payload,
            audit_payload,
            reviews,
            history,
            next_action=next_action,
            input_errors=input_errors,
        )
    except Exception as error:  # The retrospective artifact must survive malformed inputs.
        input_errors.append(
            f"retrospective_build_error:{type(error).__name__}:{error}"
        )
        payload = build_retrospective(
            {}, {}, [], [], input_errors=input_errors
        )
    _write(args.json_out, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    _write(args.markdown_out, render_markdown(payload))
    _append_history(args.history, payload, history)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if not evaluate_retrospective(payload) else 1


if __name__ == "__main__":
    raise SystemExit(main())
