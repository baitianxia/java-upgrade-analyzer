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
