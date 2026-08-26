# Cache Evidence Correctness Remediation Plan

**Goal:** Preserve performance gains while preventing incomplete, stale, or
environment-mismatched cache evidence from affecting conclusions.

## Task 1: Step1 scan completeness

- Add failing tests for post-hash archive read failure and embedded metadata
  failure.
- Return explicit scan completeness and failure details internally.
- Cache only complete scans; add archive byte and nested-entry observability.
- Run Step1 packaged dependency and observability suites.

## Task 2: Step4 comparison provenance

- Add failing tests for same-stat tool mutation, target-JDK invalidation,
  successful process without fresh XML, cached XML/row disagreement, and exact
  process counts.
- Bind target JDK and Java runtime identity into cache identity.
- Require fresh XML and reparse cached XML before returning rows.
- Run Step4 stability and final-artifact policy suites.

## Task 3: Step5 complete and deterministic indexes

- Add failing tests for missing member-index JARs, incomplete business scans,
  and duplicate physical hits arriving in different orders.
- Refuse to persist incomplete indexes and fall back to exhaustive scanning.
- Sort and deduplicate by complete physical-edge identity.
- Run Step5 key-matching, bytecode graph, and evidence-policy suites.

## Task 4: Acceptance

- Run all focused suites and the complete unit suite.
- Run cold/warm pinned real-project parity and fault injection.
- Run `quality_gate.py --profile step5` and `git diff --check`.
- Commit only after every correctness gate passes.
