# Real Project Fault Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that every eligible real-project gate detects a deliberately removed analyzer edge while its independent final-artifact Oracle remains unchanged.

**Architecture:** Run the ordinary exhaustive API and physical-edge reconciliation first. For each declared mutation, copy the analyzer-side edge set, remove one analyzer occurrence that the Oracle independently proves, reconcile into an isolated fault report, and require the result to fail with a missing-edge verdict. Production analyzer output and Oracle evidence are never modified.

**Tech Stack:** Python unittest, CSV edge ledgers, final-artifact classfile Oracle, javap, JSON reports.

## Global Constraints

- Never use analyzer output as Oracle.
- Never sample changed APIs; selected, analyzed, and independently accounted API counts must be equal.
- A case passes only when the clean run passes, the injected run fails for the expected reason, and the clean evidence remains unchanged.
- Fault injection is test-harness behavior and must not enter the production Step5 execution path.

---

### Task 1: Add a typed fault-injection contract

**Files:**
- Modify: `scripts/real_project_regression.py`
- Test: `tests/test_real_project_regression.py`

- [x] Add failing tests for a declared `drop_analyzer_edge` mutation and unsupported mutation rejection.
- [x] Add `required_fault_injections` to `RealProjectCase` and validate known mutation names.
- [x] Run the focused tests and confirm they pass.

### Task 2: Implement analyzer-edge deletion and fail-closed evaluation

**Files:**
- Modify: `scripts/real_project_regression.py`
- Test: `tests/test_real_project_regression.py`

- [x] Add a failing test that starts from a correct analyzer/Oracle pair.
- [x] Delete exactly one analyzer physical occurrence while retaining the independent Oracle scan.
- [x] Assert the injected reconciliation is blocking with exactly one or more missing edges.
- [x] Assert no injectable edge, unsupported mode, or a non-blocking mutation fails the real-project case.

### Task 3: Integrate with real-project status and persisted evidence

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/fixtures/real_projects/<new-case>.json`
- Test: `tests/test_real_project_regression.py`

- [x] Persist mutation input, removed occurrence, verdict counts, and isolated evidence paths.
- [x] Add a blocking quality signal when a required mutation does not prove gate sensitivity.
- [x] Register the mutation requirement on full-population real-project cases; framework topology never limits API population.
- [x] Run clean and injected gates on the existing pinned MyBatis XML calibration case and verify clean evidence hashes are unchanged.

### Task 4: Complete performance and continuous-regression contracts

**Files:**
- Modify: `scripts/real_project_regression.py`
- Test: `tests/test_real_project_regression.py`
- Modify: `docs/developer/quality.md`

- [x] Record per-API time, per-thousand-class scan time, JAR rescan count, javap invocation count, and peak RSS.
- [x] Add relative-baseline thresholds bound to Git revision and artifact SHA.
- [x] Reject stale baselines and regressions beyond the declared thresholds.
- [ ] Run focused, Step5 benchmark, and full-suite verification after the RuoYi convergence changes.

### Task 5: Validate a full dependency-upgrade population

- [x] Derive all Step1 dependency changes from pinned before/after RuoYi Fat JARs.
- [x] Feed all 2,185 Step4 API changes into Step5 without framework or owner filtering.
- [x] Reconcile every selected API and every retained physical edge.
- [x] Detect and fix split runtime provider, duplicated constructor-owner parsing, and field-type/constant conflation defects.
- [x] Add independent raw classfile and JDK `jdeps` authorities.
- [ ] Persist the pinned RuoYi case, artifact hashes, topology facts, and performance baseline.
