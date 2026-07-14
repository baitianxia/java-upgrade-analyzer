# Step5 Evidence Model Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a typed, pure Step5 evidence decision model, migrate packaged-bytecode conclusions through it, and validate the model against every selected API in a new Spring framework-callback real project.

**Architecture:** A new `step5_evidence_model.py` module owns immutable evidence/path/decision types, module ownership classification, and a pure decision function. Existing scanners continue collecting facts during Phase 1; `_build_packaged_dependency_hit_result` converts its candidate paths into typed paths, invokes the policy, and applies a compatibility patch to `TraceResult`. The real-project runner pins and audits `spring-guides/gs-messaging-rabbitmq` using final-artifact bytecode and the existing independent `javap` Oracle.

**Tech Stack:** Python 3 standard library, dataclasses/enums, unittest, Java `javap`, Maven, Spring Boot executable Jars.

## Global Constraints

- No new runtime dependency or non-Codex plugin installation.
- Final-artifact bytecode is authoritative for runtime call edges.
- `application_owned` identifies an internal module, never a business entry.
- Only complete, non-ambiguous business/framework paths may produce `reachable`.
- Existing Step5/Step6 report schemas remain compatible.
- Every production change follows a failing-test-first TDD cycle.
- The full unit suite and pinned real-project guards must pass before completion.

---

### Task 1: Typed Evidence and Pure Decision Policy

**Files:**
- Create: `scripts/step5_evidence_model.py`
- Create: `tests/test_step5_evidence_model.py`

**Interfaces:**
- Produces: `ModuleScope`, `EvidenceFailure`, `PhysicalCallEdge`, `ReachabilityPath`, `AnalysisDecision`, `classify_module_scope()`, `decide_analysis()`, and `decision_to_trace_patch()`.
- Consumes: plain mappings from current catalog/hit/path records; no import from `confidence_weighted_tracer.py`.

- [ ] **Step 1: Write failing ownership tests**

Test that `coord == "__business__"` maps to `BUSINESS_CLASSES`, `application_owned=True` maps to `INTERNAL_MODULE`, ordinary coordinates map to `EXTERNAL_DEPENDENCY`, and incomplete provenance maps to `UNKNOWN`.

- [ ] **Step 2: Run ownership tests and verify RED**

Run: `python3 -m unittest tests.test_step5_evidence_model.EvidenceModelTest.test_module_scope_classification -v`

Expected: import failure because `step5_evidence_model.py` does not exist.

- [ ] **Step 3: Implement immutable model types and ownership classifier**

Use frozen dataclasses and a string enum. `ReachabilityPath` contains `path_text`, `entry_scope`, `complete`, `ambiguous`, `truncated`, `stop_reason`, `depth`, and immutable edge evidence.

- [ ] **Step 4: Run ownership tests and verify GREEN**

Run the command from Step 2. Expected: `OK`.

- [ ] **Step 5: Write failing decision truth-table tests**

Cover complete business path, framework path, internal-only path, ambiguous path, blocking parse failure, complete miss, preserved API, and positive evidence coexisting with a non-blocking failure.

- [ ] **Step 6: Run decision tests and verify RED**

Run: `python3 -m unittest tests.test_step5_evidence_model -v`

Expected: failures for missing `decide_analysis()` behavior.

- [ ] **Step 7: Implement pure decision policy and compatibility patch**

`decide_analysis()` returns `AnalysisDecision` without mutating inputs. `decision_to_trace_patch()` returns a mapping for `analysis_status`, `is_reachable`, `reason_code`, `reachable_note`, `direct_callers`, and `business_reach_depth`.

- [ ] **Step 8: Run model tests and verify GREEN**

Run: `python3 -m unittest tests.test_step5_evidence_model -v`. Expected: `OK`.

### Task 2: Packaged-Bytecode Compatibility Adapter

**Files:**
- Modify: `scripts/confidence_weighted_tracer.py:4449-4652`
- Modify: `tests/test_step5_key_matching.py`
- Test: `tests/test_step5_evidence_model.py`

**Interfaces:**
- Consumes: `ReachabilityPath`, `EvidenceFailure`, `decide_analysis()`, and `decision_to_trace_patch()` from Task 1.
- Produces: unchanged `TraceResult` report fields for callers.

- [ ] **Step 1: Write failing adapter parity tests**

Create cases for direct business hit, internal hit bridged to business, internal-only hit, all-ambiguous hit, mixed exact-internal plus ambiguous-business hit, and framework-activated path. Assert both typed decision and legacy `TraceResult` fields.

- [ ] **Step 2: Run parity tests and verify RED**

Run the named tests from `tests.test_step5_key_matching` and verify failure because the packaged builder does not call the new policy.

- [ ] **Step 3: Convert packaged path details to typed paths**

Keep existing path discovery and evidence rendering, but replace direct final-status assignment in `_build_packaged_dependency_hit_result()` with typed path construction and one `decide_analysis()` call. Apply the returned compatibility patch to `TraceResult`.

- [ ] **Step 4: Run parity and Step5 tests**

Run: `python3 -m unittest tests.test_step5_evidence_model tests.test_step5_key_matching -q`

Expected: all tests pass.

- [ ] **Step 5: Add a source guard against new direct packaged decisions**

Add a test that inspects `_build_packaged_dependency_hit_result()` and rejects direct assignments to `analysis_status`, `is_reachable`, or `reason_code` outside the compatibility patch application.

- [ ] **Step 6: Run the guard and verify GREEN**

Run the guard test directly. Expected: `OK`.

### Task 3: New Real-Project Callback Fixture

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`
- Create: `tests/fixtures/real_projects/gs-messaging-rabbitmq.json`
- Create: `tests/fixtures/real_projects/gs-messaging-rabbitmq-changed-apis.csv`

**Interfaces:**
- Produces: a pinned `RealProjectCase` named `gs-messaging-rabbitmq` with required topology `framework_callback` and an explicit API denominator.
- Consumes: checkout under `/private/tmp/gs-messaging-rabbitmq/complete` and its Maven-built executable Jar.

- [ ] **Step 1: Clone and pin the official project**

Run `git clone https://github.com/spring-guides/gs-messaging-rabbitmq.git /private/tmp/gs-messaging-rabbitmq`, record `git rev-parse HEAD`, and never use a moving branch in the fixture.

- [ ] **Step 2: Build the complete application**

Run `mvn -q -DskipTests package` in `/private/tmp/gs-messaging-rabbitmq/complete`. Record final artifact path and SHA-256.

- [ ] **Step 3: Independently enumerate callback-body API instructions**

Locate every production `@RabbitListener` callback in the final Jar. Use `javap -c -p -s` to enumerate every executable method/field instruction in each callback body. Exclude constructors, compiler scaffolding, and calls whose owner is the callback class itself only when the exclusion is recorded in the fixture.

- [ ] **Step 4: Create the explicit changed-API denominator**

Write one CSV row for every selected callback-body API with owner, member, descriptor-derived signature, symbol kind, and coordinate. The Oracle must verify every row; no sampling is allowed.

- [ ] **Step 5: Write failing fixture contract tests**

Assert pinned revision/SHA, non-empty explicit API denominator, `framework_callback` topology, exact API-row count, and canonical callback-to-API physical edges.

- [ ] **Step 6: Register the real-project case and verify fixture tests**

Add the case to `CASES` and make fixture tests pass without weakening existing gates.

### Task 4: Run the New Project and Regress Every Defect

**Files:**
- Modify as defects require, limited to the responsible Step5 modules.
- Modify: focused test files corresponding to each defect.

**Interfaces:**
- Consumes: the pinned case from Task 3.
- Produces: per-API system/Oracle comparison with zero unverified selected APIs.

- [ ] **Step 1: Run the real-project case**

Run: `python3 scripts/real_project_regression.py --case gs-messaging-rabbitmq --report-root /private/tmp/jua-evidence-model-audit --json-out /private/tmp/jua-evidence-model-audit/result.json`

- [ ] **Step 2: Audit every API and edge**

For every selected API, compare status, full path, entry role, and each physical edge against `javap`. Treat any incorrect, unverified, missing, or extra selected API as a failure.

- [ ] **Step 3: For each defect, write the smallest failing regression**

The test must reproduce the defect without the real checkout where practical and must fail for the observed reason before production code changes.

- [ ] **Step 4: Implement the minimal model-based fix**

Extend typed evidence/path/policy behavior where possible. Do not add a project-name special case or another direct conclusion branch.

- [ ] **Step 5: Re-run focused tests and the complete real-project audit**

Expected: every selected API verified, no incorrect conclusions, required callback topology observed, and performance within the case budget.

### Task 5: Verification, Review, and Delivery

**Files:**
- Modify only if verification reveals a defect.

**Interfaces:**
- Produces: a reviewed commit containing Phase 1 and the new real-project regression.

- [ ] **Step 1: Run focused suites**

Run: `python3 -m unittest tests.test_step5_evidence_model tests.test_step5_key_matching tests.test_real_project_regression tests.test_artifact_bytecode_catalog -q`

- [ ] **Step 2: Run the full suite**

Run: `python3 -m unittest discover -s tests -q`. Expected: zero failures.

- [ ] **Step 3: Run static verification**

Run `python3 -m py_compile` for every modified script and `git diff --check`.

- [ ] **Step 4: Request independent read-only review**

Review must focus on false-positive/false-negative policy, evidence completeness, legacy parity, API denominator independence, and performance.

- [ ] **Step 5: Commit and push**

Commit only after all gates pass, then push `codex/step5-bytecode-index-optimization`.

