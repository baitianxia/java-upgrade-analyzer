# Quality Convergence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every current correctness and performance blocker through invariant-level fixes, then prove convergence on the complete Pig API population.

**Architecture:** Centralize edge admission around exact method identity and keep the shared graph append-only. Treat Oracle evidence as a capability-bearing, byte-verified trust boundary rather than a collection of names. Derive ownership from active build state and immutable final artifacts.

**Tech Stack:** Python 3 unittest, Java/JVM classfiles, JDK javap/jdeps, Maven, Spring Boot Fat Jars, Git.

## Global Constraints

- No new real project until Pig passes all gates.
- No threshold relaxation, evidence downgrade, or sampling.
- Use TDD and preserve 804/804 API scope.
- Run independent review after each root-cause cluster.
- Do not merge while any Critical, Important, unverified API, or performance regression remains.

---

### Task 1: Append-Only Graph And Exact Self Recursion

**Files:**
- Modify: `scripts/confidence_weighted_tracer.py`
- Test: `tests/test_step5_key_matching.py`

**Interfaces:**
- Consumes: runtime bytecode matches with caller owner, method, and descriptor.
- Produces: one exact self-recursion predicate shared by single, batch, and closure scans.

- [x] Add compiled-class regressions for `Target.entry -> Target.changed` in single, batch, and closure paths.
- [x] Add an order-invariance regression proving closure expansion does not delete pre-existing graph edges.
- [x] Run the regressions and verify failures identify owner-wide exclusion and graph mutation.
- [x] Replace owner-wide exclusion with exact caller method plus descriptor comparison.
- [x] Remove shared `reverse_edges` deletion and use lookup-local filtering only.
- [x] Run focused Step5 tests and request independent review of this cluster.

### Task 2: Oracle Trust Boundary

**Files:**
- Modify: `scripts/exhaustive_api_oracle.py`
- Modify: `scripts/real_project_regression.py`
- Test: `tests/test_exhaustive_api_oracle.py`
- Test: `tests/test_real_project_regression.py`

**Interfaces:**
- Consumes: Oracle record, evidence path, declared digest, locked artifact digest, capability declaration.
- Produces: verified record or explicit provenance failure.

- [ ] Add regressions for missing evidence files, digest mismatch, duplicate invented authorities, and child records without artifact SHA.
- [ ] Verify each regression fails under current validation.
- [ ] Read evidence bytes at audit time and compare the actual SHA-256.
- [ ] Require every evidence-bearing child record to declare the locked artifact SHA.
- [ ] Replace authority-count trust with explicit closed-world/executable/artifact-bound capability checks.
- [ ] Preserve the two-authority rule for weaker negative evidence.
- [ ] Run Oracle tests and request independent review of this cluster.

### Task 3: Effective Maven Ownership And Fat Jar Paths

**Files:**
- Modify: `scripts/analysis_contract.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Modify: `scripts/real_project_regression.py`
- Test: `tests/test_analysis_contract.py`
- Test: `tests/test_real_project_regression.py`
- Test: `tests/test_step5_key_matching.py`

**Interfaces:**
- Consumes: active Maven model, reactor closure, final-artifact nested entry identity.
- Produces: application-owned or external classification with evidence.

- [ ] Add inactive-profile and explicitly-active-profile reactor regressions.
- [ ] Add a Fat Jar class API chain regression through an internal nested module.
- [ ] Verify current ownership and Oracle path behavior fail the regressions.
- [ ] Restrict reactor discovery to unprofiled and actually activated modules.
- [ ] Carry internal nested-module ownership into class-path Oracle traversal.
- [ ] Run focused ownership/Fat Jar tests and request independent review.

### Task 4: Effective Fault Injection

**Files:**
- Modify: `scripts/fault_injection.py`
- Test: `tests/test_fault_injection.py`

**Interfaces:**
- Consumes: one original analyzer edge.
- Produces: a provably different descriptor mutation and mutation metadata.

- [ ] Add a regression whose original descriptor is `(I)V`.
- [ ] Verify the current mutation is unchanged and the test fails.
- [ ] Select a deterministic descriptor guaranteed to differ and reject no-op mutations.
- [ ] Run the complete fault-injection suite.

### Task 5: Performance Without Coverage Loss

**Files:**
- Modify: `scripts/s4_jar_compare.py`
- Modify: `scripts/real_project_regression.py`
- Modify only evidence-preserving Step1/Step5 paths identified by profiling.
- Test: corresponding performance and real-project tests.

**Interfaces:**
- Consumes: the same artifact/API population and immutable evidence inputs.
- Produces: semantically identical outputs within the pinned relative baseline.

- [ ] Profile the removed-JAR export and JDK Oracle subprocess counts from the fresh Pig report.
- [ ] Add semantic-equivalence tests around any batching or caching change.
- [ ] Batch removed-JAR and class Oracle tool invocations without changing API or edge identities.
- [ ] Re-run focused tests and compare semantic fingerprints.

### Task 6: Final Convergence Gate

**Files:**
- Update: `docs/superpowers/plans/2026-07-20-quality-convergence.md`
- Update: `tests/fixtures/real_projects/pig-v4-full-artifact-discovery.json` only for newly verified immutable facts, never thresholds.

**Interfaces:**
- Consumes: unchanged implementation tree after Tasks 1-5.
- Produces: merge decision backed by fresh evidence.

- [ ] Run focused suites for every root-cause cluster.
- [ ] Run `python3 -m unittest` and verify zero failures.
- [ ] Run `python3 -m compileall -q scripts tests` and `git diff --check`.
- [ ] Run Pig with `--full-step4-apis` and verify 804/804, fault injection, edge reconciliation, cache equivalence, memory, and performance.
- [ ] Request independent review and resolve every Critical/Important finding through a new failing regression.
- [ ] Commit, merge to `main`, push, and remove the feature branch only after every preceding checkbox passes.
