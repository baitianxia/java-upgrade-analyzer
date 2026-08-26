# Step5 Full Evidence Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route every Step5 evidence producer, graph enrichment, path builder, and final conclusion through typed contracts, one graph-ingestion boundary, and one decision policy while preserving report compatibility and independently verifying every real-project API.

**Architecture:** Collectors return immutable `CollectorBatch` values; `ingest_collector_batches()` alone validates and merges post-source edges into the existing graph; tracing builds immutable `EvidenceEnvelope` values; `decide_analysis()` alone creates conclusions; a terminal renderer creates the legacy Step5 report shape. Structural tests prohibit every former bypass.

**Tech Stack:** Python 3 standard library, frozen dataclasses/enums, unittest, AST architecture tests, Java classfiles and `javap`, Maven-built executable Jars, existing real-project regression runner.

## Global Constraints

- Do not add runtime dependencies or install plugins.
- Current final-artifact evidence is authoritative for runtime edges.
- Semantic framework edges must never claim physical-bytecode authority.
- Internal-module ownership alone never proves business reachability.
- Positive conclusions require complete paths; negative conclusions require complete per-API coverage.
- Preserve Step5 CSV/JSON, query-index, and Step6 compatibility at the terminal renderer.
- Every production change follows a demonstrated RED-GREEN TDD cycle.
- Do not add repository-name, module-name, or sample-name production branches.
- Do not duplicate final-artifact scans or `javap` work.

---

### Task 1: Typed Collector and Envelope Contracts

**Files:**
- Modify: `scripts/step5_evidence_model.py`
- Modify: `tests/test_step5_evidence_model.py`

**Interfaces:**
- Produces: `EvidenceAuthority`, `EvidenceProvenance`, `CollectedEdge`, `CoverageRecord`, `CollectorBatch`, `EvidenceEnvelope`, `decide_envelope()`, and deterministic mapping serializers.
- Consumes: existing `ModuleScope`, `EvidenceFailure`, `EvidenceConcern`, `PreservationEvidence`, `ReachabilityPath`, and `decide_analysis()`.

- [ ] **Step 1: Write failing immutable-contract tests**

Add tests that construct a valid batch and reject missing collector identity, invalid SHA, physical authority on semantic edges, and a complete-negative envelope with incomplete coverage.

```python
batch = CollectorBatch(
    collector="business_bytecode",
    version="1",
    edges=(CollectedEdge(
        caller_symbol="com.acme.App.run()",
        callee_symbol="com.vendor.Api.call()",
        edge_kind="bytecode_method_invocation",
        semantic=False,
        owner_scope=ModuleScope.BUSINESS_CLASSES,
        provenance=EvidenceProvenance(
            authority=EvidenceAuthority.CURRENT_FINAL_ARTIFACT,
            artifact_sha256="a" * 64,
            artifact_entry="BOOT-INF/classes/com/acme/App.class",
        ),
    ),),
)
```

- [ ] **Step 2: Run the contract tests and verify RED**

Run: `python3 -m unittest tests.test_step5_evidence_model -v`

Expected: import or construction failures for the new types.

- [ ] **Step 3: Implement immutable contracts and validation**

Use frozen dataclasses. `CollectorBatch.__post_init__()` validates collector/version,
edge identities, semantic/authority consistency, and SHA format. Add
`collector_batch_to_mapping()` and `evidence_envelope_to_mapping()` with stable
ordering and JSON-safe values.

- [ ] **Step 4: Add envelope decision truth-table tests**

Cover complete business, activated framework, internal-only, ambiguous, blocking
failure, conflict, incomplete coverage, complete miss, and preservation.

- [ ] **Step 5: Implement `decide_envelope()` and verify GREEN**

`decide_envelope(envelope)` delegates policy only after deriving
`complete_scan=all(applicable coverage is complete)`; incomplete applicable
coverage becomes a blocking `INCOMPLETE_EVIDENCE_COVERAGE` failure.

Run: `python3 -m unittest tests.test_step5_evidence_model -v`

- [ ] **Step 6: Commit Task 1**

```bash
git add scripts/step5_evidence_model.py tests/test_step5_evidence_model.py
git commit -m "refactor: add typed Step5 collector contracts"
```

### Task 2: Single Evidence Ingestion Boundary

**Files:**
- Create: `scripts/step5_evidence_ingestion.py`
- Create: `tests/test_step5_evidence_ingestion.py`
- Create: `tests/test_step5_architecture_boundaries.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`

**Interfaces:**
- Consumes: `CollectorBatch` and the existing enhanced source graph.
- Produces: `EvidenceRegistry.from_batches()`, `EvidenceRegistry.ingest_into()`, `ingest_collector_batches(graph, batches) -> IngestionResult`, deterministic `CallEdge` conversion, and ingestion metrics.

- [ ] **Step 1: Write failing ingestion tests**

Test exact edge conversion, semantic-edge tagging, deterministic deduplication,
artifact-provenance rejection, unknown ownership rejection, and typed failure
retention. Assert that the registry identity resolves every merged edge.

- [ ] **Step 2: Run ingestion tests and verify RED**

Run: `python3 -m unittest tests.test_step5_evidence_ingestion -v`

Expected: module import failure.

- [ ] **Step 3: Implement the ingestor**

Define:

```python
@dataclass(frozen=True)
class IngestionResult:
    merged_edges: int
    duplicate_edges: int
    rejected_edges: int
    failures: tuple[EvidenceFailure, ...]

def ingest_collector_batches(graph, batches: Iterable[CollectorBatch]) -> IngestionResult:
    registry = EvidenceRegistry.from_batches(tuple(batches))
    return registry.ingest_into(graph)
```

Store immutable records under `graph.step5_evidence_registry` and collector
coverage under `graph.step5_collector_coverage`.

- [ ] **Step 4: Write structural RED tests**

Use AST to allow post-source `graph.reverse_edges` mutation only inside
`ingest_collector_batches()`. Initially list the known violations in framework,
indirect usage, business bytecode, and engine-specific mergers; assert the final
required list is empty so the test fails now.

- [ ] **Step 5: Wire an empty ingestion boundary into Step5**

Create the ingestion call after source graph construction and before tracing. Do
not migrate collectors in this task; preserve behavior with no batches.

- [ ] **Step 6: Run ingestion and engine contract tests**

Run: `python3 -m unittest tests.test_step5_evidence_ingestion tests.test_step5_architecture_boundaries tests.test_step5_key_matching -v`

The architecture test remains RED until Tasks 3 and 4; ingestion tests must pass.

- [ ] **Step 7: Commit Task 2**

```bash
git add scripts/step5_evidence_ingestion.py scripts/s5_call_chain_engine_integrated.py tests/test_step5_evidence_ingestion.py tests/test_step5_architecture_boundaries.py
git commit -m "refactor: add one Step5 evidence ingestion boundary"
```

### Task 3: Business Bytecode and Indirect Evidence Migration

**Files:**
- Modify: `scripts/business_bytecode_graph.py`
- Modify: `scripts/indirect_usage_analyzer.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Modify: `tests/test_business_bytecode_graph.py`
- Modify: `tests/test_indirect_usage_analyzer.py`
- Modify: `tests/test_step5_evidence_ingestion.py`

**Interfaces:**
- Produces: `collect_business_bytecode_batch(source_roots, artifact_catalog, cache_path) -> CollectorBatch` and `collect_indirect_usage_batch(graph_snapshot, api_rows, source_roots) -> CollectorBatch`.
- Removes: production use of `merge_business_bytecode_edges()` and `analyze_and_merge_indirect_usages()`.

- [ ] **Step 1: Write failing bytecode-batch parity tests**

For direct method, constructor, field, reflection, unresolved caller, parse failure,
and current-final-artifact SHA cases, compare typed batch identities to the old
collector output.

- [ ] **Step 2: Verify bytecode tests RED, implement typed collection, verify GREEN**

Run the named bytecode tests before and after implementation. The collector may
reuse parsing caches but may not receive or mutate the graph.

- [ ] **Step 3: Write failing indirect-batch tests**

Cover exact reflection, dynamic member, method handle, expression language,
resource reference, source read failure, and per-API coverage.

- [ ] **Step 4: Verify indirect tests RED, implement typed collection, verify GREEN**

Return findings as concerns, read failures as `EvidenceFailure`, and the complete
analyzer matrix as `CoverageRecord` values. Do not mutate graph attributes.

- [ ] **Step 5: Replace both engine mergers with the shared ingestor**

Pass both batches in one ordered call. Derive existing graph statistics from
`CollectorBatch.metrics` and `IngestionResult`.

- [ ] **Step 6: Delete production merger calls and run structural guard**

Run: `python3 -m unittest tests.test_business_bytecode_graph tests.test_indirect_usage_analyzer tests.test_step5_evidence_ingestion tests.test_step5_architecture_boundaries -v`

Expected: no direct-mutation violations remain in these two collectors.

- [ ] **Step 7: Run real guards for direct, reflection, and internal-module topologies**

Run the permanent `gs-multi-module` and reflection/dynamic-class cases declared in
`scripts/real_project_regression.py`. Require exact per-API Oracle agreement.

- [ ] **Step 8: Commit Task 3**

```bash
git add scripts/business_bytecode_graph.py scripts/indirect_usage_analyzer.py scripts/s5_call_chain_engine_integrated.py tests/test_business_bytecode_graph.py tests/test_indirect_usage_analyzer.py tests/test_step5_evidence_ingestion.py tests/test_step5_architecture_boundaries.py
git commit -m "refactor: ingest bytecode and indirect evidence uniformly"
```

### Task 4: All Framework Adapter Migration

**Files:**
- Modify: `scripts/framework_adapters.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Modify: `tests/test_framework_adapters.py`
- Modify: `tests/test_step5_evidence_ingestion.py`
- Modify: `tests/test_step5_architecture_boundaries.py`

**Interfaces:**
- Produces: each existing `run_*_adapter(source_roots, artifact_catalog=None)` entry point returns `CollectorBatch`; `run_framework_adapters(source_roots, output_path, artifact_catalog=None)` returns an immutable tuple of batches; `serialize_framework_batches(batches, output_path)` writes diagnostics.
- Removes: `attach_framework_edges_to_graph()`.

- [ ] **Step 1: Add a parameterized RED contract for all nine adapters**

Assert each adapter returns a typed batch and has collector/version, typed edges,
typed failures/concerns, coverage, and metrics. Include not-applicable results.

- [ ] **Step 2: Add semantic-authority and activation mutation tests**

For SPI, Spring callback, transaction proxy, Spring Data, MyBatis, dynamic proxy,
and declarative client evidence, remove or corrupt registration, activation,
artifact SHA, and target identity. Require no high-confidence merged edge.

- [ ] **Step 3: Migrate adapter normalization**

Convert adapter-private parser output immediately into typed records. Exact
framework dispatch remains semantic and carries physical evidence references where
required. Diagnostic JSON is serialized from typed batches.

- [ ] **Step 4: Replace framework graph attachment with shared ingestion**

Remove `attach_framework_edges_to_graph()` from the engine. Framework runtime
entry registries must be derived by the ingestor from typed semantic edges.

- [ ] **Step 5: Run framework and architecture suites**

Run: `python3 -m unittest tests.test_framework_adapters tests.test_step5_evidence_ingestion tests.test_step5_architecture_boundaries tests.test_step5_key_matching -v`

Expected: all nine adapters pass and no framework direct graph mutation remains.

- [ ] **Step 6: Run callback/proxy real projects**

Run the permanent RabbitMQ, transaction, Dubbo/security, and both MyBatis cases.
Every selected API and semantic reference must exactly match its Oracle.

- [ ] **Step 7: Commit Task 4**

```bash
git add scripts/framework_adapters.py scripts/s5_call_chain_engine_integrated.py tests/test_framework_adapters.py tests/test_step5_evidence_ingestion.py tests/test_step5_architecture_boundaries.py
git commit -m "refactor: migrate framework adapters to typed evidence"
```

### Task 5: Envelope-First Tracing and Terminal Rendering

**Files:**
- Modify: `scripts/step5_evidence_model.py`
- Modify: `scripts/confidence_weighted_tracer.py`
- Modify: `scripts/enhanced_output_formatter.py`
- Modify: `tests/test_step5_evidence_model.py`
- Modify: `tests/test_step5_key_matching.py`
- Modify: `tests/test_step5_architecture_boundaries.py`

**Interfaces:**
- Produces: `TraceSeed`, `EvidenceEnvelope`, `AnalysisOutcome`, and `render_trace_result(seed, outcome)`.
- Removes: `decision_to_trace_patch()` and intermediate reads/writes of final conclusion fields.

- [ ] **Step 1: Write terminal-renderer parity tests**

For every decision state, compare current CSV/JSON-facing fields, path details,
evidence paths, metrics, versions, and verification commands against the new
renderer output.

- [ ] **Step 2: Write path-builder RED tests**

Assert direct source, packaged bytecode, framework runtime, indirect usage,
conflict, truncation, behavior change, and preservation builders return envelopes
without assigning final fields.

- [ ] **Step 3: Migrate path builders in behavior-preserving groups**

Each group constructs `ReachabilityPath`, failures, concerns, coverage, and
rendering details. It never consults a provisional final status.

- [ ] **Step 4: Add the terminal renderer and remove compatibility patching**

Call `decide_envelope()` once after path collection and pass the immutable outcome
to `render_trace_result()`. Remove `decision_to_trace_patch()` from production.

- [ ] **Step 5: Strengthen architecture tests**

Reject protected conclusion assignments outside the terminal renderer and reject
production calls to `decision_to_trace_patch()`. Require every `TraceResult`
creation to occur in the renderer.

- [ ] **Step 6: Run tracer, formatter, query, and Step6 compatibility tests**

Run: `python3 -m unittest tests.test_step5_evidence_model tests.test_step5_key_matching tests.test_s5_query_call_chain tests.test_step6_report -v`

- [ ] **Step 7: Commit Task 5**

```bash
git add scripts/step5_evidence_model.py scripts/confidence_weighted_tracer.py scripts/enhanced_output_formatter.py tests/test_step5_evidence_model.py tests/test_step5_key_matching.py tests/test_step5_architecture_boundaries.py
git commit -m "refactor: finalize Step5 conclusions from evidence envelopes"
```

### Task 6: Exact Accuracy, Mutation, and Performance Audit

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `scripts/topology_coverage.py`
- Modify: `tests/test_real_project_regression.py`
- Modify: `tests/test_topology_coverage.py`
- Modify: real-project manifests only when reviewed evidence fields change.

**Interfaces:**
- Consumes: immutable collector batches, evidence registry, envelopes, and outcomes.
- Produces: exact-set per-API reconciliation and performance/architecture gates.

- [ ] **Step 1: Add registry-to-rendered-path reconciliation**

Fail when any rendered edge lacks a registry identity, any registry target is
undeclared, or any selected API lacks complete applicable coverage.

- [ ] **Step 2: Add full mutation matrix**

Delete, add, corrupt, relabel, duplicate, truncate, timeout, reorder, and conflict
evidence. Run each mutation three times and require stable failure codes.

- [ ] **Step 3: Run every permanent real-project case**

For every selected API compare status, path, physical edge, semantic reference,
ownership, artifact entry, SHA, and coverage against the independent Oracle. No
sampling is permitted.

- [ ] **Step 4: Add a new project only for a missing topology**

Compute topology coverage first. If proxy, callback, reflection, internal module,
same-Jar bridge, cross-Jar bridge, XML/resource, and direct business call are all
covered, do not add another project. Otherwise pin one official project that adds
the missing topology and audit every selected API.

- [ ] **Step 5: Enforce performance budgets**

Require zero duplicate artifact scans, bounded `javap` tasks, reviewed graph
ingestion time, and no greater-than-25-percent regression per pinned case.

- [ ] **Step 6: Commit Task 6**

```bash
git add scripts/real_project_regression.py scripts/topology_coverage.py tests/test_real_project_regression.py tests/test_topology_coverage.py tests/fixtures/real_projects
git commit -m "test: enforce end-to-end Step5 evidence accuracy"
```

### Task 7: Final Verification and Delivery

**Files:**
- Modify only files required by demonstrated verification failures.

**Interfaces:**
- Produces: verified, reviewed, committed, and pushed full-chain migration.

- [ ] **Step 1: Run focused suites**

Run all evidence-model, ingestion, architecture, bytecode, indirect, framework,
tracer, query, formatter, topology, and real-project tests. Require zero failures.

- [ ] **Step 2: Run the full suite twice**

Run: `python3 -m unittest discover -s tests -p 'test_*.py'`

Require the same test count and zero failures twice to detect order/state leakage.

- [ ] **Step 3: Run static checks**

Run `python3 -m py_compile` for every modified script, `git diff --check`, and the
AST architecture guards.

- [ ] **Step 4: Request independent review**

Review false positives, false negatives, coverage completeness, evidence
authority, ownership, exception handling, determinism, compatibility, and
performance. Resolve every correctness blocker.

- [ ] **Step 5: Commit remaining review fixes and push**

Push `codex/step5-bytecode-index-optimization` only after the worktree is clean,
local and remote commits match, and all accuracy gates pass.
