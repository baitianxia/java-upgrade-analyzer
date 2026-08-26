# Test Round Retrospective Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require every real-project test round to produce an auditable retrospective and block case-by-case fixes or unreviewed repeated root causes.

**Architecture:** Add a pure retrospective module/CLI that consumes existing runner and quality-audit JSON plus an optional reviewed-findings ledger, emits JSON/Markdown/history, and returns nonzero when reflection is incomplete. Integrate it after quality-signal audit in Step5 and release gates.

**Tech Stack:** Python standard library, `unittest`, existing `quality_gate.py` task model.

## Global Constraints

- Analyzer output must never be used as its own oracle.
- P0/P1 findings require explicit root cause, escape reason, regression reference, optimization action, resolution scope, and lifecycle status.
- `case_patch` cannot close a P0/P1 finding.
- Repeated root-cause families require architecture review.
- Performance and topology deltas are first-class retrospective facts.

---

### Task 1: Retrospective Model And Gate

**Files:**
- Create: `scripts/test_round_retrospective.py`
- Create: `tests/test_test_round_retrospective.py`

**Interfaces:**
- Consumes: real-project result JSON, quality-audit JSON, optional reviewed-findings JSON and history JSON.
- Produces: `build_retrospective(real_payload, audit_payload, reviews, history) -> dict`, `evaluate_retrospective(payload) -> list[str]`, JSON/Markdown/history files, and CLI exit status.

- [x] Write failing tests for clean rounds, missing review fields, `case_patch`, repeated root causes, incomplete oracle/performance facts, topology deltas and rotate decisions.
- [x] Run `python3 -m unittest tests.test_test_round_retrospective` and verify failures are caused by the missing module.
- [x] Implement stable finding IDs, factual aggregation, review validation, trend comparison, next-project decision and deterministic JSON/Markdown rendering.
- [x] Re-run `python3 -m unittest tests.test_test_round_retrospective` and require all tests to pass.

### Task 2: Quality Gate Integration

**Files:**
- Modify: `scripts/quality_gate.py`
- Modify: `tests/test_quality_gate.py`

**Interfaces:**
- Consumes: real-project JSON and quality-signal audit JSON paths already created by `build_plan`.
- Produces: `test_round_retrospective` gate task after `quality_signal_audit`, with JSON, Markdown and history outputs under `report_root`.

- [x] Add failing plan-order tests for Step5/release and skip-real behavior.
- [x] Run `python3 -m unittest tests.test_quality_gate` and verify the new assertions fail.
- [x] Add the retrospective task constructor and append it after signal audit.
- [x] Re-run `python3 -m unittest tests.test_quality_gate` and require all tests to pass.

### Task 3: Policy Documentation And Full Verification

**Files:**
- Modify: `docs/developer/quality.md`
- Modify: `SKILL.md`
- Modify: `RUNBOOK.md`

**Interfaces:**
- Documents the mandatory artifact paths, required review fields, blocking conditions and project rotation rule.

- [x] Document the mandatory retrospective after every real-project round and its honest status vocabulary.
- [x] Run `python3 -m unittest tests.test_test_round_retrospective tests.test_quality_gate tests.test_quality_signal_audit tests.test_real_project_regression`.
- [x] Run `python3 -m unittest discover -b -s tests -p 'test_*.py'`.
- [x] Run `python3 -m py_compile scripts/*.py` and `git diff --check`.
