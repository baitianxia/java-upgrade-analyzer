# Step5 Full Evidence Migration Design

## Objective

Complete the migration started by the Step5 evidence-model Phase 1 work. Every
Step5 conclusion must be derived from validated typed evidence through one policy
boundary. Framework adapters, bytecode collectors, indirect-usage collectors,
path builders, and output rendering may not independently reinterpret evidence or
assign a final API status.

Accuracy means that positive conclusions require a complete proven path, negative
conclusions require complete coverage, incomplete evidence fails closed, and every
selected API is reconciled against an independent final-artifact Oracle. Passing
unit tests alone is not an accuracy claim.

## Current Boundary

Phase 1 introduced immutable ownership, path, failure, concern, preservation, and
decision types in `step5_evidence_model.py`. It also established a single policy
write boundary in `confidence_weighted_tracer.py`.

The remaining legacy paths are:

1. framework adapters return free-form dictionaries and
   `attach_framework_edges_to_graph()` writes the reverse graph directly;
2. `analyze_and_merge_indirect_usages()` writes graph edges, findings, and coverage
   directly;
3. business-bytecode collection uses a collector-specific dictionary followed by
   a collector-specific graph merger;
4. path builders render and mutate legacy `TraceResult` fields before or while
   constructing typed paths;
5. `decision_to_trace_patch()` copies policy output back into mutable legacy
   conclusion fields.

The migration is incomplete while any of these paths remains an accepted
production route.

## Chosen Architecture

### Typed Collector Batches

Extend `step5_evidence_model.py` with immutable types shared by every collector:

- `EvidenceAuthority`: source AST, current final artifact, packaged runtime,
  framework semantic, resource configuration, or runtime observation;
- `EvidenceProvenance`: artifact path, SHA-256, outer artifact entry, class/resource
  entry, parser, line or instruction offset, and evidence source;
- `CollectedEdge`: exact caller and callee identities, edge kind, ownership,
  confidence, ambiguity, activation conditions, and provenance;
- `CollectorFailure`: typed blocking/non-blocking collection failure;
- `CoverageRecord`: collector and per-API completeness with explicit reason codes;
- `CollectorBatch`: collector identity/version plus immutable edges, failures,
  concerns, findings, coverage, and metrics.

No collector may return a final status. Free-form metadata is allowed only inside
an immutable metadata tuple after required fields validate.

### Single Evidence Ingestion Boundary

Add `step5_evidence_ingestion.py`. Its `ingest_collector_batches(graph, batches)`
function is the only post-source-graph function allowed to mutate
`graph.reverse_edges`.

The ingestor will:

1. validate collector schema and API identities;
2. validate artifact SHA and evidence authority requirements;
3. reject semantic edges presented as physical bytecode instructions;
4. classify business, internal-module, external-dependency, and unknown ownership
   through `classify_module_scope()`;
5. deduplicate stable edge identities deterministically;
6. convert validated evidence into the existing `CallEdge` representation needed
   by the reverse tracer;
7. retain an immutable evidence registry on the graph for path construction and
   report output.

Source parsing may build the initial source graph. All later enrichments, including
business bytecode, framework semantics, and indirect calls, pass through this
single boundary.

### Collector Migration

Migrate collectors in this order:

1. business final-artifact bytecode;
2. indirect reflection, method-handle, resource, and expression evidence;
3. all nine framework adapters;
4. runtime framework callback registrations and proxy dispatch links.

Adapters may keep private parsing helpers, but their public result is a
`CollectorBatch`. JSON diagnostic files are produced by a serializer from the
typed batch, never used as the production input again.

### Evidence Envelope and Decision

Add `EvidenceEnvelope`, one per selected API. It contains target identity, ordered
candidate paths, collector failures, concerns, preservation evidence, and coverage
records. Path builders return an updated envelope and separate rendering details;
they do not modify final conclusion fields.

`decide_analysis(envelope)` remains the only policy operation. A complete business
or runtime-activated framework path can be reachable. Internal or external paths
without a business entry remain uncertain. Blocking failures and incomplete
coverage prevent static-miss conclusions. Extra or conflicting authoritative
evidence is represented explicitly and cannot be silently discarded.

### Output Boundary

Replace `decision_to_trace_patch()` with one terminal renderer that consumes the
API seed, immutable envelope, and immutable decision and creates the legacy report
shape expected by Step6. Compatibility exists only in this renderer. Intermediate
analysis code cannot read or write final legacy status fields.

Existing CSV, JSON, query-index, and Step6 schemas remain compatible. The renderer
adds evidence-envelope identifiers and completeness diagnostics where the current
schema already permits additional fields.

## Structural Enforcement

AST-based tests will fail when:

- a collector or adapter assigns `analysis_status`, `is_reachable`, or final
  `reason_code`;
- any enrichment function other than `ingest_collector_batches()` mutates
  `graph.reverse_edges`;
- production code calls `decision_to_trace_patch()`;
- path builders assign protected conclusion fields;
- a collector public API returns an untyped mapping;
- a caught collection exception is not converted to a typed failure;
- a semantic framework edge claims physical-bytecode authority;
- an absence conclusion is produced without complete per-API coverage.

These are architecture tests, not project-specific regressions.

## Accuracy Strategy

Accuracy is verified at four independent levels:

1. policy truth tables cover every combination of path ownership, completeness,
   ambiguity, conflict, failure, and preservation;
2. mutation tests delete, add, corrupt, or relabel physical and semantic evidence
   and require deterministic gate failures;
3. every selected API in each real-project fixture is compared against an
   independent `javap` or classfile Oracle, with exact-set checks for missing and
   extra evidence;
4. runtime activation is used where proxy, callback, reflection, or configuration
   semantics cannot be proven by physical instructions alone.

No `not_found_in_static_analysis` result is valid unless all applicable collector
coverage records are complete. No `reachable` result is valid unless every edge
in its rendered path maps to the immutable evidence registry.

## Performance Strategy

Collectors share the existing final-artifact inventory and class parsing caches.
The migration must not add a second artifact scan. Performance gates track visited
classes, `javap` tasks, duplicate scans, graph-ingestion time, edge count, and total
wall time. Each pinned real-project case keeps its absolute budget and rejects a
greater-than-25-percent regression against its reviewed baseline.

## Delivery Phases

### Phase 1: Contracts and Structural Red Tests

Add typed collector/envelope contracts, serializers, and AST guards. Establish
legacy parity tests before changing production collectors.

### Phase 2: Single Ingestion Boundary

Introduce the ingestor and migrate business bytecode plus indirect usage. Remove
their direct graph mutations after parity, mutation, and performance tests pass.

### Phase 3: Framework Migration

Migrate all framework adapters to typed batches and remove
`attach_framework_edges_to_graph()`. Verify callback, proxy, SPI, MyBatis, Spring
transaction, Spring Data, dynamic proxy, and declarative client behavior.

### Phase 4: Envelope-First Tracing and Terminal Rendering

Move all path construction to `EvidenceEnvelope`, remove
`decision_to_trace_patch()`, and create legacy output only in the terminal renderer.

### Phase 5: Real-Project Accuracy Audit

Run every permanent real-project guard. Add a new target only if the existing set
lacks a topology required by the migration. Audit every selected API, not a sample.

## Acceptance Criteria

- All post-source enrichment edges enter through one typed ingestion function.
- Every collector and all nine framework adapters return typed batches.
- No scanner, collector, adapter, or path builder assigns a final status.
- `decision_to_trace_patch()` and direct framework/indirect graph mergers are
  absent from production.
- Legacy Step5 and Step6 report schemas remain readable and semantically equivalent.
- Every reachable rendered edge resolves to the evidence registry.
- Every negative conclusion has complete per-API coverage.
- Missing, extra, corrupt, conflicting, and timed-out evidence mutations fail.
- Every selected API in every permanent real-project guard matches its independent
  Oracle exactly.
- Focused, full-suite, static, deterministic, and performance checks pass.
- An independent code review finds no unresolved correctness blocker before push.
