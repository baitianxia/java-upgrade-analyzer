# Active Defect Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make tests actively generate unknown evidence combinations, verify semantic invariants, kill production mutations, and enforce Oracle implementation independence.

**Architecture:** Deterministic topology models generate reproducible Maven projects and truth manifests. Metamorphic transforms assert invariant outputs, an AST mutation runner proves focused tests detect production defects, and a dependency boundary prevents analyzer/Oracle common-mode failures.

**Tech Stack:** Python 3.12 standard library, ast, unittest, javac/jar/Maven, existing quality-gate and topology registries.

## Global Constraints

- No third-party generator or mutation package is installed.
- Every random choice is derived from a recorded integer seed.
- Generated cases run the production Step4-to-Step5 path and a closed identity set.
- Mutation execution uses copied source trees and never changes the working tree.
- Oracle modules cannot import analyzer parsing, filtering, or adjudication code.

---

### Task 1: Deterministic Topology Model and Generator

**Files:**
- Create: `scripts/generated_topology.py`
- Create: `tests/test_generated_topology.py`
- Create: `tests/fixtures/generated_topologies/seeds.json`

**Interfaces:**
- Produces: `TopologySpec`, `ModuleSpec`, `ApiSpec`, `EdgeSpec`, `ActivationSpec` frozen dataclasses.
- Produces: `generate_topology(seed: int, dimensions: GenerationDimensions) -> GeneratedTopology`.
- Produces: source tree, Maven files, packaging plan, and independent truth manifest.

- [ ] Write failing deterministic serialization tests for identical and different seeds.
- [ ] Verify RED with `python3 -m unittest -v tests.test_generated_topology`.
- [ ] Implement canonical dataclasses and seeded generation for ownership, packaging, API kinds, and edge kinds.
- [ ] Compile generated same-JAR, cross-JAR, same-coordinate, overload, inheritance, constant, reflection, and callback cases.
- [ ] Assert every generated truth identity is canonical and unique.
- [ ] Run focused tests and commit `test: add deterministic topology generator`.

### Task 2: Generated End-to-End Closed-World Runner

**Files:**
- Create: `scripts/generated_topology_regression.py`
- Create: `tests/test_generated_topology_regression.py`
- Modify: `scripts/quality_gate.py`

**Interfaces:**
- Produces: `run_generated_case(case: GeneratedTopology, report_root: Path) -> GeneratedCaseResult`.
- Produces exact analyzer, Oracle, missing, extra, duplicate, and conflicting identity sets.

- [ ] Write a failing generated case whose same-coordinate inner bridge is omitted by a deliberately patched analyzer ledger.
- [ ] Verify the runner rejects the omission, extra edge, wrong descriptor, and unsupported strong conclusion.
- [ ] Implement build, production analysis, independent manifest reconciliation, and failure artifact persistence.
- [ ] Add fixed-seed core and extended profiles; core runs in quick CI and extended in release CI.
- [ ] Run `python3 -m unittest -q tests.test_generated_topology_regression` and commit `test: run generated topologies end to end`.

### Task 3: Metamorphic Invariance Engine

**Files:**
- Create: `scripts/metamorphic_regression.py`
- Create: `tests/test_metamorphic_regression.py`

**Interfaces:**
- Produces: `apply_transform(topology, transform_id) -> GeneratedTopology`.
- Produces: `semantic_digest(report_dir) -> str` over canonical API and edge ledgers.

- [ ] Write failing transforms for archive order, dependency order, module directory rename, timestamps, unrelated classes, worker counts, bridge placement, and supported JAR/WAR layout.
- [ ] Define the normalized semantic ledger fields explicitly; exclude only timestamps, absolute paths, elapsed time, and process IDs.
- [ ] Verify RED where order-sensitive fixture output differs.
- [ ] Implement transforms and semantic digest comparison.
- [ ] Require every transform to preserve API conclusions, physical edge identities, completeness, and reason codes.
- [ ] Run focused tests and commit `test: add metamorphic analyzer invariants`.

### Task 4: AST Production Mutation Runner

**Files:**
- Create: `scripts/production_mutation.py`
- Create: `tests/test_production_mutation.py`
- Create: `tests/fixtures/production_mutations.json`
- Modify: `scripts/capability_family_closure.py`

**Interfaces:**
- Produces: `MutationSpec(id, module, selector, replacement, required_tests)`.
- Produces: `run_mutant(repo_root, spec, timeout_seconds) -> MutationRun` with `killed`, `survived`, or `infrastructure_failed`.

- [ ] Write failing tests for edge-emission removal, ownership inversion, evidence-failure suppression, descriptor/coordinate drop, uncertainty promotion, artifact-binding bypass, and archive skip.
- [ ] Implement AST location validation and copied-tree mutation without shell evaluation.
- [ ] Run exact mapped unittest names in the copied tree and retain diff/log evidence.
- [ ] Reject zero-match and multi-match selectors as infrastructure failures.
- [ ] Integrate required mutant kill status into capability closure and release blocking.
- [ ] Run focused tests and commit `test: enforce production mutation detection`.

### Task 5: Oracle Independence Boundary

**Files:**
- Create: `scripts/oracle_independence.py`
- Create: `tests/test_oracle_independence.py`
- Create: `tests/fixtures/oracle_boundary.json`
- Modify: `scripts/quality_gate.py`

**Interfaces:**
- Produces: `audit_oracle_boundaries(root, policy) -> BoundaryAudit`.
- Policy declares analyzer modules, Oracle modules, data-only shared modules, and forbidden imports/calls.

- [ ] Write failing dependency tests proving Oracle import of analyzer extraction or adjudication is rejected.
- [ ] Include qualified dynamic imports and aliased imports in test fixtures.
- [ ] Implement AST import/call audit with a narrow data-schema allowlist.
- [ ] Add runtime producer provenance checks to reconciled Oracle rows.
- [ ] Add the audit to quick and release profiles as mandatory.
- [ ] Run focused and release gates, then commit `test: enforce oracle implementation independence`.

### Task 6: Program 2 Closure

**Files:**
- Modify: `tests/fixtures/capability_families.json`
- Modify: `scripts/test_round_retrospective.py`
- Modify: `.github/workflows/release-regression.yml`

**Interfaces:**
- Consumes generated, metamorphic, mutation, and boundary reports.
- Produces capability-family closure records and reproducible failure bundles.

- [ ] Register all new tests, required mutants, fixed seeds, and cross-project guards.
- [ ] Prove a surviving mutant, missing seed result, metamorphic mismatch, or boundary violation reopens the owning family.
- [ ] Run `python3 scripts/quality_gate.py --profile release --real-case guard --continue-on-failure --json-out /tmp/jua-program2-release.json`.
- [ ] Confirm zero skips and no reduced scope baselines.
- [ ] Commit `test: close active defect discovery capabilities`.
