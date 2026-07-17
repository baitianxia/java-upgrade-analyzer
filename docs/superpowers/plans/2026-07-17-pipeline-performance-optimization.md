# Pipeline Performance Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce Step1, Step4, and Step5 elapsed time and peak memory while preserving every conclusion-relevant input, API, evidence edge, reason code, and Oracle result.

**Architecture:** Add correctness-preserving observability first, then introduce content-addressed caches and bounded-memory parsing at the archive/tool boundaries. Step5 optimization reuses immutable artifact indexes and reduces retained representations without changing candidate scope or evidence decisions.

**Tech Stack:** Python 3 standard library, `zipfile`, `tempfile`, SHA-256 content identities, `unittest`, Maven/JApiCmp, existing real-project regression and quality-gate scripts.

## Global Constraints

- Analyzer output must never be used as its own Oracle.
- Cache misses, corruption, or identity mismatch must execute the complete uncached path.
- No optimization may reduce archive, class, API, physical-edge, semantic-evidence, failure, or fault-injection scope.
- Canonical API conclusions, reason codes, analyzer edge ledger, and independent Oracle reconciliation must remain identical.
- Performance acceptance happens only after correctness parity passes.

---

### Task 1: Step1 and Step4 Resource Observability

**Files:**
- Modify: `scripts/step1_observability.py`
- Modify: `scripts/s1_dep_diff.py`
- Modify: `scripts/s4_jar_compare.py`
- Test: `tests/test_step1_observability.py`
- Test: `tests/test_step4_stability.py`

**Interfaces:**
- Produces Step1 timing rows for `peak_rss_mb`, archive bytes, nested entries, and cache counters.
- Produces Step4 timing details for `peak_rss_mb`, Java invocations, and cache counters.

- [ ] Write tests that require resource metrics in successful timing output.
- [ ] Run the focused tests and verify the new assertions fail.
- [ ] Add platform-normalized peak RSS and monotonic counters without affecting result construction.
- [ ] Run focused observability and stability tests until green.
- [ ] Commit the independently verified observability change.

### Task 2: Step1 Bounded Nested-JAR Parsing

**Files:**
- Modify: `scripts/s1_dep_diff.py`
- Test: `tests/test_step1_packaged_deps.py`

**Interfaces:**
- Produces `_inspect_packaged_archive(path)` records with the existing schema and deterministic order.
- Adds a bounded seekable nested-entry spool used only during coordinate inspection.

- [ ] Write tests that force a nested JAR above the in-memory threshold and assert exact record parity and spool cleanup.
- [ ] Run the focused test and verify failure because the bounded spool path is absent.
- [ ] Stream outer entries into `SpooledTemporaryFile`, computing SHA-256 during the single copy.
- [ ] Preserve malformed-entry evidence and deterministic output exactly.
- [ ] Run Step1 packaged-dependency, observability, and final-artifact policy tests.
- [ ] Commit the independently verified bounded-memory parser.

### Task 3: Step1 Content-Addressed Inventory Cache

**Files:**
- Modify: `scripts/s1_dep_diff.py`
- Test: `tests/test_step1_packaged_deps.py`

**Interfaces:**
- Cache key: final artifact SHA-256 plus cache schema version.
- Cache value: normalized packaged dependency records and integrity metadata.

- [ ] Write cache hit, artifact mutation, schema mismatch, and corrupt-cache fallback tests.
- [ ] Verify the tests fail before implementation.
- [ ] Implement atomic cache writes and fail-open-to-full-scan reads.
- [ ] Assert cached and fresh records are byte-for-byte equivalent after canonical serialization.
- [ ] Run focused Step1 tests and commit.

### Task 4: Step4 Tool Digest and Comparison Cache

**Files:**
- Modify: `scripts/s4_jar_compare.py`
- Test: `tests/test_step4_stability.py`
- Test: `tests/test_final_artifact_only_policy.py`

**Interfaces:**
- Cache key: old/new JAR SHA-256, JApiCmp SHA-256, options, target JDK, and schema version.
- Cached payload: successful raw XML, normalized API rows, parser metadata, and integrity SHA-256.

- [ ] Write a test proving the JApiCmp tool digest is computed once per unchanged tool identity.
- [ ] Write fresh/hit/mutation/corruption/failed-process tests for comparison caching.
- [ ] Verify all new tests fail for the intended missing behavior.
- [ ] Add process-local tool digest memoization.
- [ ] Add atomic persistent cache writes and strict validation on reads.
- [ ] Ensure failures and timeouts are never stored as successful cache entries.
- [ ] Run focused Step4 and final-artifact policy tests and commit.

### Task 5: Step5 Persisted Candidate Index and Retained Memory

**Files:**
- Modify: `scripts/confidence_weighted_tracer.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Test: `tests/test_step5_key_matching.py`
- Test: `tests/test_step5_evidence_policy.py`

**Interfaces:**
- Persisted index key: artifact SHA-256, target JDK, parser/index schema, and scan scope.
- Index records select candidates only; normal parsers continue producing evidence.

- [ ] Write tests for exact candidate parity, invalidation, corrupt fallback, and no scope reduction.
- [ ] Verify tests fail before implementation.
- [ ] Persist and atomically load the immutable member-candidate index.
- [ ] Intern immutable identities and release temporary candidate containers after deterministic merge.
- [ ] Assert conclusion, reason-code, and physical-edge-ledger parity against the uncached path.
- [ ] Run focused Step5 tests and commit.

### Task 6: End-to-End Correctness and Performance Acceptance

**Files:**
- Modify: `scripts/real_project_regression.py` only if additional parity fields are required.
- Modify: `tests/fixtures/real_projects/*.json` only for newly measured, SHA-bound baselines.
- Test: `tests/test_real_project_regression.py`

**Interfaces:**
- Consumes all Step1/Step4/Step5 observability and correctness artifacts.
- Produces cold/warm measurements and blocking correctness/performance signals.

- [ ] Run focused suites for all modified stages.
- [ ] Run the complete unit suite.
- [ ] Run pinned real-project cold analysis and archive canonical outputs.
- [ ] Run warm analysis and compare every API, reason code, physical edge, and Oracle result.
- [ ] Run every configured fault injection and require detection.
- [ ] Compare median elapsed time and peak RSS against the frozen baseline.
- [ ] Run the release quality gate and commit only SHA-bound baseline updates supported by the measurements.
