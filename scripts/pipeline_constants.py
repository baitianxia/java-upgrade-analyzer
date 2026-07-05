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
    "jar_compare",
    "call_chain",
]

STEP1_ARTIFACTS_DIRNAME = "s1_artifacts"
PER_DEPENDENCY_DIRNAME = "s4_per_dependency"
PER_DEPENDENCY_SUMMARY_FILE = "summary.json"
PER_DEPENDENCY_RESOLVED_TARGETS_FILE = "resolved_targets.csv"
PER_DEPENDENCY_REMOVED_JAR_SYMBOLS_FILE = "removed_jar_symbols.csv"
PER_DEPENDENCY_CANDIDATE_HITS_FILE = "candidate_hits.csv"
STEP3_RISK_CANDIDATES_FILE = "s3_risk_candidates.csv"
STEP5_ARTIFACT_BYTECODE_DIRNAME = "s5_artifact_bytecode"
STEP5_ARTIFACT_BYTECODE_CATALOG_FILE = "s5_artifact_bytecode_catalog.json"
STEP5_ARTIFACT_BYTECODE_INDEX_FILE = "s5_artifact_bytecode_index.json"

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
