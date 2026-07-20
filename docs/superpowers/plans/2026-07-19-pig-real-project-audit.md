# Pig Real Project Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Analyze the complete API upgrade surface of fixed Pig v4.0.0 and v4.1.0 Fat Jars, correct generalized analyzer defects, and promote the topology to a reproducible regression.

**Architecture:** Treat the two SHA-bound `pig-boot` Fat Jars as the only runtime truth, derive every changed API from Step4, and reconcile every analyzer conclusion and physical edge against independent classfile, javap, XML, and Spring framework evidence. Fix capability-level defects with RED regressions before rerunning the full audit; never use source or loose target classes as runtime proof.

**Tech Stack:** Python 3.12, unittest, Maven 3.9.12, Java 24 targeting Java 17, Spring Boot Fat Jars, javap, ZIP/classfile parsers.

## Global Constraints

- Base source revision is `7197ec39e16e45f35ef8b47d381f2c833eaf66ed` (tag `v4.0.0`).
- Current source revision is `f4e5a3a4b902dc00c192b878d7587cec93698803` (tag `v4.1.0`).
- Target module is `pig-boot` from the first Step1 call.
- Audit all Step4 changed APIs; MyBatis APIs are not a privileged subset.
- Oracle evidence must be independent of analyzer conclusions.
- Preserve fail-closed archive validation and bounded time and memory.
- Do not add Pig-specific package, coordinate, class, or method branches to production code.

---

### Task 1: Accept Bounded Enterprise Fat Jars

**Files:**
- Modify: `scripts/artifact_safety.py`
- Modify: `tests/test_artifact_safety.py`

**Interfaces:**
- Consumes: `inspect_archive_bytes(content, **limits)` and `inspect_archive(path, **limits)`.
- Produces: a named default aggregate entry budget that accepts a 110,000-entry nested Fat Jar while explicit smaller budgets remain fail-closed.

- [x] **Step 1: Write the failing enterprise Fat Jar regression**

Generate nested ZIP members in memory with more than 100,000 aggregate entries and assert the default inspection is safe, reports the exact aggregate count, and completes within the existing bounded metadata-scan budget.

- [x] **Step 2: Run the focused test and verify RED**

Run: `PYTHONPATH=scripts python3 -m unittest tests.test_artifact_safety.ArtifactSafetyTest.test_enterprise_fat_jar_stays_within_default_aggregate_entry_budget -v`

Expected: FAIL with `ARCHIVE_ENTRY_COUNT_EXCEEDED`.

- [x] **Step 3: Raise only the named aggregate entry budget**

Define the default total-entry limit once in `artifact_safety.py`, keep caller overrides unchanged, and leave uncompressed size, expansion ratio, nested size, path, duplicate, and depth checks untouched.

- [x] **Step 4: Verify GREEN and explicit rejection**

Run the new regression plus `test_rejects_nested_archive_depth_and_entry_budget`; both must pass, proving normal large archives and explicit low-budget rejection coexist.

### Task 2: Derive the Complete Pig API Population

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`
- Create: `tests/fixtures/real_projects/pig-v4-full-artifact-discovery.json`

**Interfaces:**
- Consumes: the two fixed `pig-boot.jar` artifacts and their fixed source revisions.
- Produces: `CASES["pig-v4-full-artifact-discovery"]` in discovery mode with Step1 artifact derivation, full Step4 selection, topology requirements, five standard fault injections, and relative performance gating.

- [x] **Step 1: Rerun Step1 on the two final artifacts**

Run direct artifact mode with `target_module=pig-boot` and confirm both artifact digests and all changed dependency rows are persisted.

- [x] **Step 2: Run Step4 without probe selection**

Derive the complete changed API CSV from all changed final-artifact dependencies and verify `step5_selected_apis == step4_changed_apis`.

- [x] **Step 3: Add the discovery case regression**

Assert fixed revisions, fixed artifact paths, `case_mode="discovery"`, no declared API subset, standard fault injections, and full-population accounting.

- [x] **Step 4: Register the fixed real-project fixture**

Persist repository, revisions, artifact SHA-256 values, materialization command, population contract, required topologies, performance scope, and every discovered generalized finding.

### Task 3: Reconcile Every API and Physical Edge

**Files:**
- Modify only the generalized collector or adjudicator owning a demonstrated failing regression.
- Add the minimal regression to the corresponding existing `tests/test_*.py` module before each production change.

**Interfaces:**
- Consumes: full Step4 API CSV, final-artifact classfile scan, javap output, Mapper XML, Spring metadata, and framework callback rules.
- Produces: a complete per-API Oracle ledger, physical-edge reconciliation, and explicit proof for each `reachable`, `uncertain`, `not_found_in_static_analysis`, or `not_analyzed` conclusion.

- [x] **Step 1: Generate independent evidence for every API**

Run independent classfile and JDK javap scanners over the final artifact, use jdeps only as a positive fallback when javap is incomplete, resolve Mapper XML and callback registrations separately, and reject any API without an independent verdict.

- [x] **Step 2: Compare every analyzer conclusion**

Require zero incorrect, zero unverified, zero Oracle conflicts, and exact selected/accounted population equality.

- [x] **Step 3: Reconcile every physical edge in both directions**

Require no missing, extra, identity-mismatched, provenance-invalid, or conflicting edge occurrence.

- [x] **Step 4: Fix each generalized defect with RED-GREEN evidence**

For every mismatch, first add the smallest topology-based regression, verify RED, change the owning general capability, run focused GREEN tests, then rerun the complete Pig population.

### Task 4: Prove Gate Sensitivity and Performance

**Files:**
- Modify: `tests/fixtures/real_projects/pig-v4-full-artifact-discovery.json`
- Modify only if a generalized gate defect is demonstrated: `scripts/fault_injection.py`, `scripts/real_project_regression.py`, or their matching tests.

**Interfaces:**
- Consumes: clean reconciled analyzer and Oracle ledgers.
- Produces: five detected fault injections and SHA-bound time, memory, javap, jdeps, duplicate-scan, and per-class performance baselines.

- [x] **Step 1: Run every applicable fault injection**

Run all five standard mutations against the independently observed Pig consumer edges and require every injected omission, addition, descriptor corruption, Oracle digest corruption, and Oracle truncation to fail the gate.

- [x] **Step 2: Record cold-run performance**

Persist Step1, Step4, Step5, Oracle, per-API, per-1000-class, javap/jdeps, duplicate scan, and peak RSS metrics tied to the artifact SHA.

- [x] **Step 3: Run deterministic equivalence**

Repeat Step5 with warm caches and require the canonical conclusion and path fingerprint to match the cold run.

### Task 5: Verify, Review, and Integrate

**Files:**
- Modify: `tests/fixtures/topologies/prior_matrix.json`
- Modify: `docs/superpowers/plans/2026-07-19-pig-real-project-audit.md`

**Interfaces:**
- Consumes: all focused regressions and the complete Pig audit.
- Produces: a reviewed commit merged to `main`, pushed to `origin/main`, with the feature branch removed.

- [x] **Step 1: Run focused suites and compile checks**

Run archive safety, real-project regression, topology coverage, framework adapter, Step1, Step4, and Step5 test modules plus `compileall`.

- [x] **Step 2: Run the complete unittest suite**

Require zero failures and report the exact test count and elapsed time.

- [ ] **Step 3: Run independent code review**

Reject unresolved Critical or Important correctness, security, performance, or test-quality findings.

- [x] **Step 4: Preserve topology rotation evidence without false promotion**

Keep the independently observed Pig topologies in the discovery fixture and audit output. Do not add them to `prior_matrix.json` until a passing guard or convergence case binds them to reviewed evidence.

- [ ] **Step 5: Commit, merge, push, and clean up**

Commit verified changes, fast-forward or merge to `main`, push `origin/main`, remove the worktree and feature branch, and verify local/remote main equality without modifying the user zip.
