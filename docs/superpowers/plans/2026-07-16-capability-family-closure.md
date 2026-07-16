# Capability Family Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make architecture-level capability closure executable so a real-project finding cannot be closed by a project-specific or partial-path fix.

**Architecture:** A versioned capability registry defines falsifiable invariants, all production paths, generalized tests, mutation probes, and real-project guards. A pure closure validator binds retrospective reviews to that registry and the current real-project result; Step5 and release gates block when any family is only documentarily closed.

**Tech Stack:** Python 3 standard library, `unittest`, JSON fixtures, existing `quality_gate.py` and `test_round_retrospective.py` task model.

## Global Constraints

- Real projects expose capability gaps; they are not implementation units.
- Analyzer output must never be used as its own Oracle.
- A fixed P0/P1 finding must cover every registered production path.
- Positive, negative, mutation, and cross-project evidence are all mandatory when declared by the invariant.
- Missing assets, missing tests, parser failures, and Oracle conflicts fail closed.
- Development governance must not be copied into `SKILL.md` or `RUNBOOK.md`.

---

### Task 1: Capability Registry Contract

**Files:**
- Create: `scripts/capability_family_closure.py`
- Create: `tests/test_capability_family_closure.py`
- Create: `tests/fixtures/capability_families.json`

**Interfaces:**
- Produces: `load_registry(path: Path) -> dict`, `validate_registry(registry: dict) -> list[str]`, and stable family/invariant lookup.

- [ ] Write failing tests that reject duplicate families, empty invariants, missing production paths, missing test categories, duplicate test references, and unknown root-cause mappings.
- [ ] Run `python3 -m unittest tests.test_capability_family_closure` and verify failure is caused by the missing module.
- [ ] Implement strict registry loading and validation without accepting implicit defaults.
- [ ] Add the initial registry taxonomy and mark families without executable evidence as open.
- [ ] Re-run `python3 -m unittest tests.test_capability_family_closure` and require all registry tests to pass.

### Task 2: Finding Closure Validation

**Files:**
- Modify: `scripts/capability_family_closure.py`
- Modify: `tests/test_capability_family_closure.py`

**Interfaces:**
- Consumes: registry, real-project payload, reviews payload, and retrospective history.
- Produces: `build_closure_report(registry, real_payload, reviews, history) -> dict` and `evaluate_closure(report) -> list[str]`.

- [ ] Write failing tests for a renamed case patch, partial production-path audit, misspelled extra path, unloadable unittest reference, absent negative test, absent mutation test, non-passing real-project guard, and repeated family without architecture decision.
- [ ] Add a passing test where all paths, tests, and current guards satisfy one invariant.
- [ ] Run the focused suite and verify only the new closure assertions fail.
- [ ] Implement deterministic report construction and fail-closed evaluation.
- [ ] Re-run the focused suite and require all closure tests to pass.

### Task 3: Retrospective Binding

**Files:**
- Modify: `scripts/test_round_retrospective.py`
- Modify: `tests/test_test_round_retrospective.py`

**Interfaces:**
- Consumes: the new review fields `capability_family`, `invariant_id`, `audited_production_paths`, `generalized_regression_tests`, `negative_regression_tests`, `mutation_tests`, `cross_project_guards`, and `architecture_decision`.
- Produces: reviews that can be independently checked by the closure gate.

- [ ] Write failing tests proving `status=fixed` cannot omit capability binding and repeated families cannot omit an architecture decision.
- [ ] Preserve accepted uncertainty semantics without allowing it to masquerade as fixed.
- [ ] Implement strict field and type validation while keeping stable finding IDs unchanged.
- [ ] Re-run retrospective and closure suites together.

### Task 4: Artifact Identity And Ownership Invariant Matrix

**Files:**
- Create: `tests/test_artifact_identity_ownership_invariants.py`
- Modify: `tests/fixtures/capability_families.json`
- Modify as required by failing generalized tests: `scripts/step5_evidence_ingestion.py`, `scripts/step5_evidence_model.py`, `scripts/confidence_weighted_tracer.py`, `scripts/business_bytecode_graph.py`

**Interfaces:**
- Produces: generated normal-JAR, internal-module, nested-Fat-JAR, same-coordinate, and unrelated-same-name layouts with one logical call graph.

- [ ] Write fixture builders that compile one logical graph and package all five layouts from the same classfiles.
- [ ] Add positive equivalence assertions for canonical API identity and physical call edges.
- [ ] Add negative assertions for unrelated same-name owners and descriptor mismatches.
- [ ] Add boundary assertions rejecting stale class directories and unverified final-artifact SHA values.
- [ ] Add mutation tests that remove a nested entry and corrupt ownership metadata; require the analyzer or quality gate to fail closed.
- [ ] Run the invariant suite and record every production-path failure before editing production code.
- [ ] Trace each failure to the earliest shared identity/ownership boundary and make one model-level correction at a time.
- [ ] Re-run the invariant suite after each correction and remove obsolete path-specific branches made redundant by the shared model.

### Task 5: Quality Gate Integration

**Files:**
- Modify: `scripts/quality_gate.py`
- Modify: `tests/test_quality_gate.py`
- Modify: `docs/developer/quality.md`

**Interfaces:**
- Adds: `capability_family_closure` task after `test_round_retrospective` for Step5 and release profiles.

- [ ] Write failing plan-order tests for Step5, release, and skip-real behavior.
- [ ] Add CLI JSON output under the quality-gate report root and ensure stale output is removed before execution.
- [ ] Require a nonzero closure result to block the profile even when unit tests pass.
- [ ] Document the registry, closure evidence, and prohibition on rotating projects with open repeated families.
- [ ] Re-run `tests.test_quality_gate`, retrospective, and closure suites.

### Task 6: Verification And Current-Family Audit

**Files:**
- Modify: `tests/fixtures/capability_families.json`
- Create: `docs/developer/capability-family-audit.md`

**Interfaces:**
- Produces: an evidence-backed audit separating closed, open, and blocked capability families; no family is marked closed from prose alone.

- [ ] Audit every current family against actual production paths and generalized tests.
- [ ] Mark incomplete families open and list the exact missing executable evidence.
- [ ] Run `python3 -m unittest tests.test_capability_family_closure tests.test_artifact_identity_ownership_invariants tests.test_test_round_retrospective tests.test_quality_gate`.
- [ ] Run `python3 -m unittest discover -s tests`.
- [ ] Run `python3 scripts/quality_gate.py --profile step5` while polling the process until it exits.
- [ ] Inspect the final JSON, exit code, real-project failures, skipped cases, and closure report before stating completion.
- [ ] Run `git diff --check` and review the final diff for project-specific production conditions.
