#!/usr/bin/env python3
"""Pipeline-level shared constants."""

STEP_SEQUENCE = ["step1", "step2", "step3", "step4", "step5", "step6"]

STEP_TO_MAJOR = {
    "step1": 1,
    "step2": 2,
    "step3": 3,
    "step4": 4,
    "step5": 5,
    "step6": 6,
}

INTERACTIVE_STATUS = "awaiting_user_input"

GATE_SEQUENCE = [
    "step1_scope",
    "context",
    "scan",
    "binary_generation",
    "binary_report",
]

STEP1_ARTIFACTS_DIRNAME = "s1_artifacts"
STEP1_DEPENDENCY_JARS_DIRNAME = "s1_dependency_jars"
STEP1_DEPENDENCY_JARS_MANIFEST_FILE = "dependency_jars.json"
PER_DEPENDENCY_DIRNAME = "s4_per_dependency"
PER_DEPENDENCY_SUMMARY_FILE = "summary.json"
PER_DEPENDENCY_CANDIDATE_HITS_FILE = "candidate_hits.csv"
STEP3_RISK_CANDIDATES_FILE = "s3_risk_candidates.csv"
STEP5_QUERY_INDEX_FILE = "s5_query_index.json"

# ``analysis_status=uncertain`` describes the conclusion, not whether the
# analyzer actually found a candidate usage.  Keep that evidence distinction
# orthogonal so user-facing reports do not invent a candidate path for static
# analysis blind spots such as compile-time constant inlining.
UNCERTAINTY_KIND_CANDIDATE_EVIDENCE = "candidate_evidence"
UNCERTAINTY_KIND_ANALYSIS_LIMITATION = "analysis_limitation"

DELIVERABLES_DIRNAME = "deliverables"
EVIDENCE_DIRNAME = "evidence"
RUNTIME_DIRNAME = ".runtime"

EVIDENCE_DEPENDENCIES_DIRNAME = "dependencies"
EVIDENCE_CONTEXT_DIRNAME = "context"
EVIDENCE_STATIC_SCAN_DIRNAME = "static_scan"
EVIDENCE_API_CHANGES_DIRNAME = "api_changes"
EVIDENCE_CALL_CHAIN_DIRNAME = "call_chain"

RUNTIME_STATE_DIRNAME = "state"
RUNTIME_COVERAGE_DIRNAME = "coverage"
RUNTIME_INDEXES_DIRNAME = "indexes"
RUNTIME_FINDINGS_DIRNAME = "findings"
RUNTIME_CACHE_DIRNAME = "cache"
RUNTIME_OBSERVABILITY_DIRNAME = "observability"

BLOCKED_AT_VALUES = (
    "system_source",
    "dependency_with_source",
    "dependency_without_source",
)

BLOCKED_REASON_KEYS = (
    "NO_STATIC_PATH",
    "DEPENDENCY_SOURCE_MAPPING_MISSING",
    "RESOURCE_OR_REFLECTION",
    "BEHAVIOR_CHANGED_RUNTIME_VERIFICATION",
)
