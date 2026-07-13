# Required Analysis Parsers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require JApiCmp and tree-sitter for production Java upgrade analysis and remove the user-visible degraded continuation path.

**Architecture:** Step4 and Step5 continue to auto-install their own prerequisite, then fail closed through their existing checkpoint mechanism. `run_step.py` becomes the second enforcement boundary by rejecting a degraded checkpoint response even if a stale or hand-crafted response includes it.

**Tech Stack:** Python 3, unittest, JSON interaction protocol.

## Global Constraints

- No Step4 or Step5 production continuation may depend on `allow_degraded` when JApiCmp or tree-sitter is unavailable.
- Failures must retain their existing preflight evidence files and hard-stop interaction protocol.
- Tests are written and observed failing before each behavior change.

---

### Task 1: Fail-closed checkpoint contracts

**Files:**
- Modify: `scripts/run_step.py:5048-5070`
- Modify: `tests/test_run_step_main_state.py:1312-1366`

**Interfaces:**
- Consumes: Step4 reason code `step4_japicmp_missing_need_resolution`, Step5 reason code `step5_tree_sitter_missing_need_resolution`.
- Produces: `validate_pending_interaction_response()` accepts only `japicmp_jar` for Step4 and `tree_sitter_installed=true` for Step5.

- [ ] Write tests asserting `allow_degraded=true` raises `StepError` for both reason codes.
- [ ] Run `python3 -m unittest tests.test_run_step_main_state.<new-test-names> -q` and observe failure against the existing continuation behavior.
- [ ] Remove the `allow_degraded` acceptance branches and require the concrete install confirmation fields.
- [ ] Re-run the focused tests and `tests.test_run_step_main_state -q`.
- [ ] Commit the verified contract change.

### Task 2: Remove parser-degradation interaction and execution paths

**Files:**
- Modify: `scripts/s4_jar_compare.py:1262-1360,4474-4525`
- Modify: `scripts/s5_call_chain_engine_integrated.py:465-580,760-795`
- Modify: `tests/test_step4_stability.py:230-255`
- Modify: `tests/test_step5_key_matching.py:260-290`

**Interfaces:**
- Consumes: JApiCmp/tree-sitter auto-install result and existing preflight detail writers.
- Produces: hard-stop payloads whose schemas expose no `allow_degraded`; execution returns without a fallback continuation.

- [ ] Write tests asserting both interaction schemas omit `allow_degraded` and their rerun requirements demand the installed tool.
- [ ] Run the focused tests and observe failure because the existing schemas still expose the bypass.
- [ ] Delete the Step4 and Step5 `allow_degraded` continuation branches, update user-facing text, and keep existing evidence emission.
- [ ] Re-run focused Step4/Step5 tests, then the cross-step regression suite.
- [ ] Commit the verified execution-path change.

### Task 3: Align user documentation

**Files:**
- Modify: `SKILL.md:78,156-164`
- Modify: `README.md:337-349`

**Interfaces:**
- Consumes: the fail-closed runtime behavior from Tasks 1 and 2.
- Produces: user guidance that installation is mandatory, with no degraded option described.

- [ ] Replace all parser-prerequisite references that offer `allow_degraded=true` with install-and-rerun instructions.
- [ ] Search `SKILL.md`, `README.md`, `scripts/s4_jar_compare.py`, `scripts/s5_call_chain_engine_integrated.py`, and `scripts/run_step.py` for parser-specific degraded continuation wording.
- [ ] Run documentation and regression verification, then commit the documentation alignment.
