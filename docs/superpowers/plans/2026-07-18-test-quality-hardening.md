# Test Quality Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make correctness, evidence completeness, mutation detection, performance scope, and real-project verification continuously enforceable.

**Architecture:** Add explicit CI tiers and preflight contracts, generalize real-project mutations behind a registry, then extend the evidence and topology models through focused TDD slices. Keep Oracle and analyzer mutation boundaries separate and fail closed on missing prerequisites.

**Tech Stack:** Python 3.12, unittest, GitHub Actions, JDK javac/javap/jdeps, Maven, ZIP/classfile fixtures.

## Global Constraints

- Never reduce analysis or Oracle scope to satisfy a budget.
- Never treat missing required tools, assets, or outputs as a passing skip.
- Never use analyzer output as Oracle input.
- Preserve current output schemas unless a task explicitly versions them.

---

### Task 1: CI enforcement tiers

**Files:**
- Modify: `.github/workflows/smoke-regression.yml`
- Create: `.github/workflows/release-regression.yml`
- Create: `tests/test_ci_quality_contract.py`
- Modify: `scripts/quality_gate.py`

**Interfaces:**
- Produces: `validate_required_tools(names: tuple[str, ...]) -> list[str]`
- Produces: workflow contracts for quick, Step5, and scheduled release gates.

- [ ] Write tests requiring `references/**`, explicit JDK/Maven setup, Step5 on `main`, scheduled release, JSON outputs, and failure on missing mandatory tools.
- [ ] Run `python3 -m unittest tests.test_ci_quality_contract -v` and observe failures.
- [ ] Implement workflow tiers and gate preflight.
- [ ] Run the focused tests and quick gate.
- [ ] Commit the independently passing CI enforcement slice.

### Task 2: Typed fault injection registry

**Files:**
- Create: `scripts/fault_injection.py`
- Create: `tests/test_fault_injection.py`
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Produces: `apply_fault_injection(mode, analyzer_rows, oracle_scan) -> MutationResult`.
- Supports: `drop_analyzer_edge`, `add_analyzer_edge`, `wrong_analyzer_descriptor`, `corrupt_oracle_digest`, `truncate_oracle_scan`.

- [ ] Write one failing test per mutation and expected blocking verdict.
- [ ] Run focused tests and verify each fails for the missing mode.
- [ ] Implement immutable mutation results and integrate the registry.
- [ ] Verify analyzer-only mutations preserve Oracle SHA and Oracle mutations are rejected as invalid truth.
- [ ] Run real-project regression unit tests and commit.

### Task 3: Artifact/source alignment evidence

**Files:**
- Create: `scripts/artifact_alignment.py`
- Create: `tests/test_artifact_alignment.py`
- Modify: `scripts/step5_evidence_ingestion.py`
- Modify: `scripts/s1_dep_diff.py`

**Interfaces:**
- Produces: `build_artifact_alignment(project, artifact, module, build) -> AlignmentRecord`.
- Consumes: Git revision, dirty paths, module, command, profile, artifact SHA-256.

- [ ] Write failing tests for clean aligned build, dirty tree, stale JAR, wrong module, wrong revision, and external unverified artifact.
- [ ] Implement the immutable alignment record and SHA/revision verification.
- [ ] Project the record through Step1 and Step5 evidence.
- [ ] Run Step1/Step5 contract tests and commit.

### Task 4: Compile-time constant dual impact

**Files:**
- Create: `scripts/constant_impact.py`
- Create: `tests/test_constant_impact.py`
- Modify: `scripts/step5_evidence_model.py`
- Modify: `scripts/real_project_regression.py`

**Interfaces:**
- Produces separate `compile_impact` and `runtime_link_impact` conclusions.

- [ ] Write failing classfile tests for ConstantValue deletion, value change, non-constant field, and source/artifact mismatch.
- [ ] Implement independent ConstantValue and caller-bytecode inspection.
- [ ] Integrate dual conclusions without manufacturing runtime edges.
- [ ] Verify the Commons Text guard and commit.

### Task 5: Framework activation and uncertain transitions

**Files:**
- Modify: `scripts/framework_adapters.py`
- Modify: `scripts/step5_evidence_model.py`
- Create: `tests/test_evidence_state_transitions.py`
- Modify: `tests/test_framework_adapters.py`
- Modify: `tests/fixtures/topologies/manifest.json`

**Interfaces:**
- Produces artifact-bound activation evidence for AOP and security filter chains.
- Produces a reason-code transition matrix for evidence add/remove operations.

- [ ] Write failing positive, inactive, and incomplete-evidence tests for AOP and filter chains.
- [ ] Write failing monotonic transition tests for every supported uncertain reason family.
- [ ] Implement artifact-bound activation records and single adjudication transitions.
- [ ] Run framework, evidence model, and topology closure tests and commit.

### Task 6: Runtime and artifact matrix

**Files:**
- Create: `tests/test_artifact_runtime_matrix.py`
- Modify: `scripts/confidence_weighted_tracer.py`
- Modify: `scripts/business_bytecode_graph.py`

**Interfaces:**
- Covers WAR layouts, MR-JAR target selection, Kotlin identities, and JDK-version-specific javap behavior.

- [ ] Add failing generated fixtures for WAR, MR-JAR base/versioned classes, and Kotlin-style bytecode identities.
- [ ] Implement only missing generalized artifact selection behavior.
- [ ] Run the matrix under available JDK tools; required CI jobs fail if tools are absent.
- [ ] Commit.

### Task 7: Hostile artifacts and performance scope

**Files:**
- Create: `scripts/artifact_safety.py`
- Create: `tests/test_artifact_safety.py`
- Create: `tests/test_end_to_end_stress.py`
- Modify: `scripts/real_project_regression.py`

**Interfaces:**
- Produces bounded ZIP/class inventory validation with typed failures.
- Produces cold/warm semantic ledger hashes and scope-preserving performance metrics.

- [ ] Write failing tests for traversal, symlink, expansion ratio, nested depth, duplicate class, malformed class, timeout cleanup, and cache determinism.
- [ ] Implement bounded validation and typed coverage failures.
- [ ] Add generated end-to-end scope/performance fixtures.
- [ ] Run stress and regression tests and commit.

### Task 8: Closure and cleanup

**Files:**
- Modify: `TODO.md`
- Modify: `docs/developer/quality.md`
- Modify: `tests/fixtures/capability_families.json`

**Interfaces:**
- Consumes all prior executable evidence and removes TODO entries only when their acceptance commands pass.

- [ ] Run focused suites for all seven tasks.
- [ ] Run `python3 scripts/quality_gate.py --profile release --real-case guard --continue-on-failure`.
- [ ] Confirm no mandatory task skipped and scope baselines did not decrease.
- [ ] Remove only completed TODO items, update capability closure evidence, and commit.
- [ ] Run a fresh final release gate and review the full diff.

