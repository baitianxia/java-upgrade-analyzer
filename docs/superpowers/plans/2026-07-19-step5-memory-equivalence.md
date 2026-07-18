# Step5 Equivalent Memory Reduction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce Step5 peak RSS without changing any analysis result or increasing median runtime.

**Architecture:** Replace full-graph copies with read-only overlays or query-scoped snapshots, keep deterministic ingestion while avoiding unnecessary sorting copies, release collector intermediates immediately after their final read, and record phase-level memory metrics. Every optimization is guarded by exact result fingerprints and benchmark gates.

**Tech Stack:** Python 3.12, `unittest`, immutable Step5 collector model, existing Step5 smoke/real-project regression harness.

## Global Constraints

- API status, reason codes, chain nodes and order, evidence, coverage and user reports must not change.
- Do not reduce `max_depth`, `max_methods`, scanned JARs, classes, APIs or adapters.
- Do not introduce degraded analysis, disk-backed graph storage, external sorting or result truncation.
- Optimized median runtime must not exceed baseline median runtime on the same fixtures.
- Peak RSS must decrease on the large synthetic benchmark.
- Commit each independently testable change separately.

---

### Task 1: Establish exact-result and memory baselines

**Files:**
- Create: `tests/test_step5_memory_equivalence.py`
- Modify: `scripts/real_project_regression.py`

**Interfaces:**
- Consumes: Step5 `summary.json`, `alerts.csv`, query-index output and `step5_perf.main`.
- Produces: `canonical_step5_result_fingerprint(report_dir: Path) -> str` and a deterministic synthetic graph/batch benchmark fixture.

- [ ] **Step 1: Write failing tests for the canonical result fingerprint**

Add tests proving that volatile paths, timestamps and new memory metrics do not affect the fingerprint, while API status, path order, hop evidence and coverage changes do affect it.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `python3 -m unittest tests.test_step5_memory_equivalence`

Expected: failure because `canonical_step5_result_fingerprint` does not exist.

- [ ] **Step 3: Implement canonicalization and fingerprinting**

Implement a helper that reads the existing machine-readable outputs, removes only explicitly volatile fields, preserves list order, serializes with stable JSON separators and returns SHA-256.

- [ ] **Step 4: Add a large deterministic ingestion fixture**

Generate repeated but uniquely keyed `CollectedEdge` values in memory. Record elapsed time, RSS before/after and merged-edge counts without writing large fixture files into the repository.

- [ ] **Step 5: Verify GREEN and record baseline**

Run the focused tests three times and save baseline median elapsed/RSS values in the test diagnostics, not as brittle absolute assertions.

- [ ] **Step 6: Commit**

```bash
git add tests/test_step5_memory_equivalence.py scripts/real_project_regression.py
git commit -m "test: establish step5 memory equivalence baseline"
```

### Task 2: Replace the indirect-analysis full graph copy with a read-only overlay

**Files:**
- Modify: `scripts/s5_call_chain_engine_integrated.py:679-691`
- Test: `tests/test_step5_memory_equivalence.py`
- Test: `tests/test_step5_key_matching.py`

**Interfaces:**
- Consumes: `graph.reverse_edges: Mapping[str, list[CallEdge]]`, `CollectorBatch.edges`.
- Produces: `_ReverseEdgeOverlay(Mapping)` and `_graph_snapshot_with_bytecode_batch(graph, batch)` with the same `.get()` behavior as the prior snapshot.

- [ ] **Step 1: Write failing overlay tests**

Cover base-only keys, overlay-only keys, combined keys, empty keys, immutability, iteration and proof that untouched base lists are not copied.

- [ ] **Step 2: Verify RED**

Run: `python3 -m unittest tests.test_step5_memory_equivalence.ReverseEdgeOverlayTest`

Expected: failure because `_ReverseEdgeOverlay` does not exist.

- [ ] **Step 3: Implement the minimal Mapping overlay**

Use `collections.abc.Mapping`. Store the base mapping by reference and only reflection evidence in `dict[str, tuple]`. Return base objects unchanged when no overlay exists and a tuple combination only for keys that contain overlay evidence.

- [ ] **Step 4: Verify behavior and exact result equality**

Run the overlay tests and the indirect/reflection Step5 tests. Compare canonical fingerprints before and after.

- [ ] **Step 5: Benchmark three runs**

Require optimized median runtime not above baseline and confirm no full base-list copies are created.

- [ ] **Step 6: Commit**

```bash
git add scripts/s5_call_chain_engine_integrated.py tests/test_step5_memory_equivalence.py tests/test_step5_key_matching.py
git commit -m "perf: overlay pending bytecode evidence without graph copy"
```

### Task 3: Replace the framework full graph snapshot with a query-scoped snapshot

**Files:**
- Modify: `scripts/step5_evidence_ingestion.py:238-270,1265-1710,1906-1955`
- Test: `tests/test_step5_evidence_ingestion.py`
- Test: `tests/test_step5_memory_equivalence.py`

**Interfaces:**
- Consumes: framework records and the pre-framework `graph.reverse_edges` mapping.
- Produces: `_framework_snapshot_keys(records) -> tuple[str, ...]` and `_snapshot_reverse_edges_for_keys(reverse_edges, keys) -> dict[str, tuple]`.

- [ ] **Step 1: Write failing tests for required-key completeness**

Create MyBatis, transaction and Spring Data records whose source identities have qualified, class, method and signature lookup variants. Assert that every key read by projection exists in the calculated key set.

- [ ] **Step 2: Verify RED**

Run: `python3 -m unittest tests.test_step5_evidence_ingestion tests.test_step5_memory_equivalence.FrameworkSnapshotTest`

Expected: failure because query-scoped snapshot helpers do not exist.

- [ ] **Step 3: Implement key discovery without changing projection**

Centralize source-key generation so the projection and snapshot builder share the same function. Freeze only selected lists as tuples before adding any framework semantic edge.

- [ ] **Step 4: Add a defensive completeness assertion in tests**

Instrument the test mapping so any unplanned key access fails. Do not add a production fallback that silently reads the mutated live graph.

- [ ] **Step 5: Verify all framework outputs and fingerprints**

Run framework ingestion, MyBatis, Spring proxy and Step5 smoke tests. Compare merged/duplicate/rejected counters and canonical results.

- [ ] **Step 6: Benchmark and commit**

```bash
git add scripts/step5_evidence_ingestion.py tests/test_step5_evidence_ingestion.py tests/test_step5_memory_equivalence.py
git commit -m "perf: snapshot only framework projection keys"
```

### Task 4: Avoid unnecessary ingestion copies and release final-use intermediates

**Files:**
- Modify: `scripts/step5_evidence_ingestion.py:1720-2040`
- Modify: `scripts/s5_call_chain_engine_integrated.py:1260-1410`
- Test: `tests/test_step5_evidence_ingestion.py`
- Test: `tests/test_step5_memory_equivalence.py`

**Interfaces:**
- Produces: `_iter_edges_stably(edges, identity)` that returns the original tuple iterator when already sorted and current `sorted` semantics otherwise.
- Preserves: `graph.step5_evidence_registry`, evidence ledger, failures, concerns and coverage contracts.

- [ ] **Step 1: Write failing stable-iteration tests**

Assert sorted input is not copied, unsorted input yields exactly the previous order, duplicates remain deduplicated and registry order is unchanged.

- [ ] **Step 2: Verify RED**

Run focused ingestion tests; expect failure because `_iter_edges_stably` does not exist.

- [ ] **Step 3: Implement stable fast path**

Perform one adjacent identity scan. Return `iter(edges)` when monotonic; otherwise return `iter(sorted(edges, key=identity))`. Do not cache identities for the entire batch.

- [ ] **Step 4: Release batches only after their final consumers**

Reorder metric/coverage extraction so `bytecode_batch`, `framework_batches`, `indirect_batch`, snapshot and temporary index references can be deleted immediately after ingestion. Call `gc.collect()` only at phase boundaries where a large object graph became unreachable; benchmark must prove it does not increase median runtime.

- [ ] **Step 5: Verify exact outputs and benchmark**

Run collector, Step5 key matching, smoke and large synthetic tests. If explicit GC increases median runtime, remove it and keep reference release only.

- [ ] **Step 6: Commit**

```bash
git add scripts/step5_evidence_ingestion.py scripts/s5_call_chain_engine_integrated.py tests/test_step5_evidence_ingestion.py tests/test_step5_memory_equivalence.py
git commit -m "perf: shorten step5 evidence intermediate lifetimes"
```

### Task 5: Add phase-level memory observability

**Files:**
- Create: `scripts/step5_memory_observer.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Modify: `scripts/confidence_weighted_tracer.py`
- Test: `tests/test_step5_memory_equivalence.py`
- Test: `tests/test_progress_logging.py`

**Interfaces:**
- Produces: `current_rss_mb() -> float`, `peak_rss_mb() -> float`, and `record_step5_memory(graph_stats, phase, graph=None, extra=None) -> dict`.
- Writes: memory samples into existing Step5 timing/observability data and concise progress logs.

- [ ] **Step 1: Write failing cross-platform observer tests**

Test Linux `/proc`, macOS `resource`/process query fallback and unavailable-metric behavior through dependency injection. Ensure failures return `0.0` and never interrupt analysis.

- [ ] **Step 2: Verify RED**

Run observer tests; expect import/function failures.

- [ ] **Step 3: Implement observer and phase hooks**

Record the six phases from the design. Count total reverse edges without materializing a flattened list. Avoid subprocess invocation on the hot per-class or per-API path.

- [ ] **Step 4: Verify observability contract**

Assert timing outputs contain phase, current RSS, peak RSS, method count, key count and edge count. Existing fields and CSV encoding remain unchanged.

- [ ] **Step 5: Commit**

```bash
git add scripts/step5_memory_observer.py scripts/s5_call_chain_engine_integrated.py scripts/confidence_weighted_tracer.py tests/test_step5_memory_equivalence.py tests/test_progress_logging.py
git commit -m "feat: record step5 phase memory usage"
```

### Task 6: Full correctness and performance gate

**Files:**
- Modify only if a test exposes a root-cause defect; each fix requires a new failing test and separate commit.

**Interfaces:**
- Consumes: all prior tasks and existing real-project fixtures.
- Produces: verified result fingerprints, timing comparison and peak-RSS comparison.

- [ ] **Step 1: Run focused correctness suites**

```bash
python3 -m unittest tests.test_step5_memory_equivalence tests.test_step5_evidence_ingestion tests.test_step5_key_matching tests.test_progress_logging
```

- [ ] **Step 2: Run core and Step5 smoke groups**

```bash
python3 scripts/smoke_regression.py --group core
python3 scripts/smoke_regression.py --group step5
```

- [ ] **Step 3: Run the complete test suite**

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

- [ ] **Step 4: Run three baseline and optimized benchmark repetitions**

Compare median total/phase elapsed time, peak RSS and canonical result fingerprints. Reject any result mismatch or median runtime increase.

- [ ] **Step 5: Run and inspect the Dubbo real-project regression**

Use the existing pinned Dubbo fixture/configuration. Compare every output fingerprint and review reachable, uncertain, not-found and not-analyzed distributions.

- [ ] **Step 6: Verify repository state**

Run `git diff --check`, inspect `git status --short`, and confirm the existing ZIP remains untracked and untouched.
