# Step1 Shallow Dependency Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Step1 discover packaged dependencies without recursively reading nested class/resource entries, while treating repeated Maven metadata according to normalized coordinate evidence.

**Architecture:** Step1 performs a shallow outer-container validation and streams only selected dependency JARs. Nested JAR parsing enumerates physical Maven metadata records by `ZipInfo`, deduplicates equal GAV values, records contradictory declarations, and leaves final coordinate reconciliation to the existing filename/runtime inventory path.

**Tech Stack:** Python 3.12 standard library (`zipfile`, `hashlib`, `tempfile`) and `unittest`.

## Global Constraints

- Do not raise the generic archive entry threshold.
- Do not recurse through nested class or resource payloads in Step1.
- Do not downgrade archive or metadata failures into API conclusions.
- Preserve outer artifact path and nested JAR SHA as physical identity evidence.
- Do not modify unrelated Step4 or Step5 behavior.

---

### Task 1: Maven Metadata Occurrence Reconciliation

**Files:**
- Modify: `tests/test_step1_packaged_deps.py`
- Modify: `scripts/s1_dep_diff.py`

**Interfaces:**
- Consumes: `_extract_packaged_dep_from_nested_jar_source(source, entry_name, content_sha256)`
- Produces: packaged row field `metadata_anomalies: list[str]`

- [ ] Add a failing test with duplicate `pom.properties` records that have the same GAV but different comments.
- [ ] Add a failing test with duplicate records at one path that declare different versions; require filename reconciliation and a non-blocking anomaly.
- [ ] Run both tests and verify the current implementation fails for the expected duplicate-occurrence reason.
- [ ] Iterate over `nested_zip.infolist()` and call `nested_zip.read(info)` so each physical record is parsed.
- [ ] Group normalized GAV candidates, collapse equal values, and retain same-path disagreement as `metadata_anomalies`.
- [ ] Increment `PACKAGED_INVENTORY_CACHE_SCHEMA_VERSION` and include the anomaly field in cache validation.
- [ ] Run the focused tests and the existing embedded-POM selection tests.

### Task 2: Step1 Shallow Dependency Scan

**Files:**
- Modify: `tests/test_step1_packaged_deps.py`
- Modify: `scripts/s1_dep_diff.py`
- Modify: `scripts/artifact_safety.py`
- Modify: `tests/test_artifact_safety.py`

**Interfaces:**
- Consumes: outer `ZipInfo` records and `_stream_nested_jar_to_spool`
- Produces: `_PackagedArchiveScanResult` with dependency rows and explicit outer-container failures

- [ ] Add a failing test whose nested class has a corrupt CRC while valid Maven metadata remains readable.
- [ ] Add a failing test for duplicate outer `BOOT-INF/lib` entry paths.
- [ ] Run both tests and verify the current recursive safety scan causes the expected failure.
- [ ] Replace Step1's call to generic recursive `inspect_archive` with shallow outer central-directory validation.
- [ ] Keep unsafe outer paths and duplicate physical dependency entries blocking.
- [ ] Stream and parse only selected dependency JARs; do not read their unrelated class/resource entries.
- [ ] Remove the uncommitted 200,000-entry threshold change and its threshold-specific regression test.
- [ ] Run the focused Step1 and generic archive-safety tests.

### Task 3: Evidence Propagation And Verification

**Files:**
- Modify: `scripts/s1_dep_diff.py`
- Test: `tests/test_step1_packaged_deps.py`

**Interfaces:**
- Consumes: packaged row `metadata_anomalies`
- Produces: Step1 dependency evidence remarks that retain metadata anomalies without changing resolution status

- [ ] Add a failing test that verifies a reconciled metadata anomaly is visible in final Step1 dependency evidence.
- [ ] Append normalized anomaly evidence to resolved and unresolved dependency remarks.
- [ ] Run `tests.test_step1_packaged_deps` and `tests.test_artifact_safety`.
- [ ] Run the complete unit-test suite.
- [ ] Run `git diff --check` and Python compilation for changed scripts.
- [ ] Request an independent review limited to Critical and Important correctness findings.
