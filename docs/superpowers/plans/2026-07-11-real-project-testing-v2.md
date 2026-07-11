# Real Project Testing V2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make real-project results prove their analyzed coverage, expose distinct conclusion gaps, align runner status with release decisions, and gate normalized performance without claiming unreviewed accuracy.

**Architecture:** Extend `RealProjectCase` with lifecycle, ground-truth, and performance policy. Build structured signals from measured result fields, then derive the case status from those signals. Keep `quality_signal_audit.py` as the independent release consumer and preserve compatibility with legacy result payloads.

**Tech Stack:** Python 3 standard library, `dataclasses`, JSON/CSV reports, `unittest`.

## Global Constraints

- Discovery and convergence cases require 100% Step4-to-Step5 API coverage.
- Guard cases must explicitly report their declared probe scope.
- Any blocking signal makes the runner status `failed`.
- Distinct reason codes and symbol kinds must not be merged into one signal.
- Performance gates may not reduce the analyzed API population.
- A case without reviewed ground truth cannot claim an accuracy pass.

---

### Task 1: Coverage Contract

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Produces: `compute_api_coverage(case_mode: str, population: int, selected: int, output_total: int) -> dict`
- Produces result fields: `case_mode`, `coverage_scope`, `api_population`, `apis_selected`, `apis_accounted`, `coverage_ratio`
- Produces signal type: `coverage_gap`

- [ ] **Step 1: Write failing tests**

Add tests that assert a discovery case with population 100 and selected 9 emits a blocking `coverage_gap`, while population 100 and selected/output 100 does not. Add a guard test that records `coverage_scope="declared_probes"` without claiming full coverage.

- [ ] **Step 2: Verify the tests fail**

Run: `python3 -m unittest tests.test_real_project_regression`

Expected: failures because lifecycle and coverage fields do not exist.

- [ ] **Step 3: Implement coverage computation**

Add `case_mode: str = "guard"` to `RealProjectCase`, configure Dubbo as `discovery`, and implement:

```python
def compute_api_coverage(case_mode, population, selected, output_total):
    ratio = selected / population if population else (1.0 if selected == 0 else 0.0)
    return {
        "case_mode": case_mode,
        "coverage_scope": "full" if case_mode in {"discovery", "convergence"} else "declared_probes",
        "api_population": population,
        "apis_selected": selected,
        "apis_accounted": output_total,
        "coverage_ratio": ratio,
    }
```

Emit `coverage_gap` when discovery/convergence coverage is below 1.0 or output total differs from selected.

- [ ] **Step 4: Verify tests pass**

Run: `python3 -m unittest tests.test_real_project_regression`

- [ ] **Step 5: Commit**

```bash
git add scripts/real_project_regression.py tests/test_real_project_regression.py
git commit -m "Gate real project API coverage"
```

### Task 2: Structured Conclusion Gaps

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `scripts/quality_signal_audit.py`
- Modify: `tests/test_real_project_regression.py`
- Modify: `tests/test_quality_signal_audit.py`

**Interfaces:**
- Produces: `group_conclusion_gaps(summary: dict) -> list[dict]`
- Extends `QualitySignal` with `reason_code`, `symbol_kind`, `sample_symbols`
- Produces signal type: `conclusion_gap`

- [ ] **Step 1: Write failing tests**

Create a summary fixture containing two unavailable-runtime-jar methods and one overload-ambiguous constructor. Assert two blocking signals with counts 2 and 1, separate reason codes, separate symbol kinds, and representative symbols.

- [ ] **Step 2: Verify the tests fail**

Run: `python3 -m unittest tests.test_real_project_regression tests.test_quality_signal_audit`

- [ ] **Step 3: Implement grouped signals**

Group `not_analyzed_apis` by `(reason_code, symbol_kind)`. Emit one P1 `conclusion_gap` per group and retain at most five stable sorted sample symbols. Fall back to the legacy aggregate capability gap only when item-level details are unavailable.

- [ ] **Step 4: Verify tests pass**

Run: `python3 -m unittest tests.test_real_project_regression tests.test_quality_signal_audit`

- [ ] **Step 5: Commit**

```bash
git add scripts/real_project_regression.py scripts/quality_signal_audit.py tests/test_real_project_regression.py tests/test_quality_signal_audit.py
git commit -m "Expose grouped real project conclusion gaps"
```

### Task 3: Status and Ground-Truth Semantics

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Produces: `derive_case_status(executed: bool, signals: list[dict], ground_truth_status: str) -> str`
- Produces result field: `ground_truth_status`
- Produces signal type: `ground_truth_insufficient`

- [ ] **Step 1: Write failing tests**

Assert that any blocking signal yields `failed`; no semantic execution yields `skipped`; a discovery case with no reviewed manifest yields blocking `ground_truth_insufficient` and status `observed`; only reviewed ground truth with no blocking signal yields `passed`.

- [ ] **Step 2: Verify the tests fail**

Run: `python3 -m unittest tests.test_real_project_regression`

- [ ] **Step 3: Implement status derivation**

Add `ground_truth_status: str = "unreviewed"` to cases. Build all signals before assigning final status. Use `observed` only when the sole blocking condition is insufficient ground truth; semantic or coverage failures take precedence and yield `failed`.

- [ ] **Step 4: Verify tests pass**

Run: `python3 -m unittest tests.test_real_project_regression`

- [ ] **Step 5: Commit**

```bash
git add scripts/real_project_regression.py tests/test_real_project_regression.py
git commit -m "Align real project status with quality signals"
```

### Task 4: Normalized Performance Envelope

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Produces: `collect_performance_envelope(summary: dict, elapsed: float, selected: int) -> dict`
- Adds case field: `max_potential_pairs_per_api: float = 0.0`

- [ ] **Step 1: Write failing tests**

Assert that 143,240,640 pairs over 5,440 APIs produces approximately 26,331 pairs per API and that exceeding a configured ceiling emits blocking `performance_regression`. Assert the metric remains visible when no ceiling is configured.

- [ ] **Step 2: Verify the tests fail**

Run: `python3 -m unittest tests.test_real_project_regression`

- [ ] **Step 3: Implement normalized metrics**

Read potential pairs and owner scans from Step5 summary performance data. Record absolute and per-API metrics plus elapsed seconds per 1,000 APIs. Configure Dubbo's initial ceiling above the observed baseline so future regressions are detectable without hiding the current value.

- [ ] **Step 4: Verify tests pass**

Run: `python3 -m unittest tests.test_real_project_regression`

- [ ] **Step 5: Commit**

```bash
git add scripts/real_project_regression.py tests/test_real_project_regression.py
git commit -m "Gate normalized real project performance"
```

### Task 5: Release Integration and Dubbo Acceptance

**Files:**
- Modify: `tests/test_quality_gate.py`
- Modify: `docs/developer/quality.md`

**Interfaces:**
- Consumes the result and signals produced by Tasks 1-4.

- [ ] **Step 1: Add release contract tests**

Assert release audit rejects `failed`, `observed`, and blocking coverage/conclusion/ground-truth signals, while retaining legacy payload compatibility.

- [ ] **Step 2: Run focused and full tests**

Run:

```bash
python3 -m unittest tests.test_real_project_regression tests.test_quality_signal_audit tests.test_quality_gate
python3 -m unittest discover -s tests -p 'test_*.py'
```

- [ ] **Step 3: Re-audit the full Dubbo result**

Run the V2 result adapter or a fresh full case and verify: coverage 1.0, separate runtime-jar and overload groups, non-passed status, candidate-pair metric present, and no accuracy-pass claim.

- [ ] **Step 4: Update quality documentation**

Document discovery/guard semantics, coverage and ground-truth gates, grouped conclusion debt, and normalized performance metrics.

- [ ] **Step 5: Commit**

```bash
git add tests/test_quality_gate.py docs/developer/quality.md
git commit -m "Document real project V2 release gates"
```

