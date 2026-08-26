# Framework Owner Artifact Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify framework-discovered business owners against their exact application-owned runtime artifact without globally poisoning unrelated API conclusions.

**Architecture:** Add one exact owner-to-artifact resolver over the shared SHA-bound fact store and use it in Spring transaction bytecode verification. Preserve fail-closed identity and ambiguity behavior while scoping missing owners to their own evidence.

**Tech Stack:** Python 3.12, unittest, javac/javap, ZIP/JAR fixtures, Step5 artifact fact store.

## Global Constraints

- Do not add project-specific coordinates, package names, or class names.
- Do not use source or stale target classes as runtime proof.
- Only application-owned catalog entries may verify business framework owners.
- Artifact mutation and duplicate owner definitions must fail closed.

---

### Task 1: Reproduce Cross-Module Owner Misrouting

**Files:**
- Modify: `tests/test_framework_adapters.py`

**Interfaces:**
- Consumes: `collect_spring_transaction_activation(artifact_catalog, source_roots, fact_store=...)`
- Produces: a regression fixture with owners split across `__business__` and an application-owned internal module.

- [x] **Step 1: Write the failing regression**

Compile two transactional service classes into separate JARs, describe both source roots,
and assert the collector verifies both owners without `FRAMEWORK_JAVAP_FAILED`.

- [x] **Step 2: Verify RED**

Run: `PYTHONPATH=scripts python3 -m unittest tests.test_framework_adapters.FrameworkAdaptersTest.test_transaction_collector_routes_internal_module_owner_to_its_artifact`

Expected: FAIL because the internal-module owner is looked up in `__business__`.

### Task 2: Implement Exact Owner Routing

**Files:**
- Modify: `scripts/framework_adapters.py`
- Modify: `tests/test_framework_adapters.py`

**Interfaces:**
- Produces: `_application_owned_entries_by_owner(entries, owners, fact_store)` returning exact assignments and explicit diagnostics.
- Consumes: `_shared_artifact_inventory`, `_catalog_entry_is_application_owned`, `_artifact_javap`.

- [x] **Step 1: Route owners by verified inventory**

Inspect each application-owned inventory, assign each requested owner only when its exact
logical class exists once, and retain identity/ambiguity diagnostics.

- [x] **Step 2: Verify GREEN**

Run the focused regression and all `tests.test_framework_adapters` tests.

- [x] **Step 3: Add ambiguity and missing-owner regressions**

Assert duplicate application-owned definitions block and a missing owner cannot erase
valid evidence from another owner.

### Task 3: Validate Architecture and Real Project

**Files:**
- Modify only if a generalized defect is found by the gates.

**Interfaces:**
- Consumes: fixed RuoYi revisions, complete API list, independent Oracle, fault-injection and performance baselines.
- Produces: fresh test and real-project evidence tied to exact commits and artifacts.

- [x] **Step 1: Run focused and full automated suites**

Run framework, Step5, compileall, diff checks, and full unittest discovery.

- [x] **Step 2: Run independent review**

Reject unresolved Critical or Important findings before integration.

- [x] **Step 3: Rerun RuoYi end to end**

Confirm the prior `GenTableServiceImpl` lookup no longer emits a global
`FRAMEWORK_JAVAP_FAILED`, then compare every API conclusion and every physical edge to
the independent Oracle. Run all configured fault injections and relative performance gates.

- [x] **Step 4: Commit only verified behavior**

Commit the generalized fix and its regression evidence; do not merge merely because the
focused RuoYi symptom disappears.
