# Production Evidence Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete automatic compile-time constant evidence and artifact-bound Spring AOP/Security activation so both remaining TODO items can be removed with real-project proof.

**Architecture:** Production collectors emit immutable SHA-bound evidence records into the existing Step5 evidence model. Independent Oracle modules use JDK tools and separately implemented parsing rules; a single adjudicator produces conclusions only after closed-world reconciliation.

**Tech Stack:** Python 3.12 standard library, unittest, JVM classfile format, javac/javap/jdeps, Maven, ZIP/JAR/WAR fixtures.

## Global Constraints

- Analyzer and Oracle parsing implementations must remain independent.
- Every changed API is reconciled; sampling is forbidden.
- Missing, failed, timed-out, conflicting, or stale evidence fails closed.
- No new Python package or Java dependency may be installed.
- Production changes follow red-green-refactor and preserve existing CSV/JSON fields.
- TODO entries are removed only after fresh release verification.

---

### Task 1: Direct Classfile Constant Evidence Collector

**Files:**
- Modify: `scripts/constant_impact.py`
- Modify: `scripts/business_bytecode_graph.py`
- Create: `tests/test_constant_evidence_extraction.py`

**Interfaces:**
- Produces: `ConstantFieldEvidence(owner, field_name, descriptor, has_constant_value, constant_value, artifact_sha256, artifact_entry, status, failures)`.
- Produces: `extract_constant_field_evidence(jar_path, owner, field_name, descriptor) -> ConstantFieldEvidence`.
- Produces: `scan_consumer_field_links(artifact_paths, owner, field_name, descriptor) -> tuple[FieldLinkEvidence, ...]`.

- [ ] **Step 1: Write failing old-field extraction tests**

Compile fixtures containing `static final String`, primitive constants, non-constant static fields, overloaded descriptors, and malformed class data. Assert exact owner/name/descriptor matching and `ConstantValue` decoding:

```python
evidence = extract_constant_field_evidence(jar, "sample.Flags", "TEXT", "Ljava/lang/String;")
self.assertEqual(evidence.status, "complete")
self.assertTrue(evidence.has_constant_value)
self.assertEqual(evidence.constant_value, "old")
self.assertEqual(evidence.artifact_sha256, sha256_file(jar))
```

- [ ] **Step 2: Run the focused test and verify RED**

Run: `python3 -m unittest -v tests.test_constant_evidence_extraction`

Expected: failures because `extract_constant_field_evidence` and evidence types do not exist.

- [ ] **Step 3: Implement direct classfile field-attribute parsing**

Reuse only low-level classfile byte readers from `business_bytecode_graph`; parse field tables and the `ConstantValue` attribute in `constant_impact.py`. Return typed incomplete evidence for malformed descriptors, unreadable archives, duplicate matching fields, and unsupported constant-pool tags.

- [ ] **Step 4: Add caller final-artifact field-link tests and implementation**

Compile one caller with `getstatic`, one caller with an inlined constant, and one unrelated same-name field. Require exact constant-pool owner/name/descriptor matching and SHA-bound class entries:

```python
links = scan_consumer_field_links([consumer_jar], "sample.Flags", "TEXT", "Ljava/lang/String;")
self.assertEqual([(item.opcode, item.consumer_owner) for item in links], [("getstatic", "app.Linked")])
```

- [ ] **Step 5: Verify collector tests and commit**

Run: `python3 -m unittest -q tests.test_constant_evidence_extraction tests.test_constant_impact tests.test_artifact_safety`

Expected: all tests pass.

Commit: `feat: extract constant and caller link evidence`

### Task 2: Step4/Step5 Constant Evidence Integration

**Files:**
- Modify: `scripts/s4_jar_compare.py`
- Modify: `scripts/s4_contract.py`
- Modify: `scripts/confidence_weighted_tracer.py`
- Modify: `scripts/step5_evidence_model.py`
- Modify: `scripts/enhanced_output_formatter.py`
- Modify: `tests/test_step4_stability.py`
- Modify: `tests/test_step5_key_matching.py`

**Interfaces:**
- Consumes: `extract_constant_field_evidence(...)` and `scan_consumer_field_links(...)`.
- Produces: `constant_field_evidence_json` in Step4 rows without removing legacy `old_field_has_constant_value`.
- Produces: `constant_impact_evidence` containing old artifact evidence and current consumer-link evidence.

- [ ] **Step 1: Write failing Step4 integration tests**

Assert that removed/value-changed fields carry a structured evidence reference, SHA, descriptor, and completeness status, while ordinary methods and classes remain unchanged.

- [ ] **Step 2: Verify Step4 RED**

Run: `python3 -m unittest -v tests.test_step4_stability.Step4StabilityTest.test_constant_change_records_old_artifact_constant_evidence`

Expected: assertion failure because Step4 does not invoke automatic extraction.

- [ ] **Step 3: Integrate Step4 extraction with fail-closed errors**

Call the collector only for field constant change families. Preserve existing columns and serialize the typed record deterministically. Extraction failure must produce explicit incomplete evidence, not `false`.

- [ ] **Step 4: Write failing Step5 automatic adjudication tests**

Cover constant deletion with inlined caller, deletion with retained `getstatic`, value change, non-constant field, missing old artifact, and source/artifact mismatch. Do not place `old_field_has_constant_value` manually in the API row.

- [ ] **Step 5: Integrate current-final-artifact link collection**

Build `compile_impact` and `runtime_link_impact` exclusively through `classify_constant_impact`; attach complete evidence to every early-return and normal trace path.

- [ ] **Step 6: Verify Step4/Step5 integration and commit**

Run: `python3 -m unittest -q tests.test_step4_stability tests.test_constant_impact tests.test_step5_key_matching tests.test_real_project_regression`

Expected: all tests pass and no output schema compatibility failure.

Commit: `feat: automate constant impact evidence flow`

### Task 3: Independent Constant Oracle and Commons Text Guard

**Files:**
- Create: `scripts/constant_impact_oracle.py`
- Create: `tests/test_constant_impact_oracle.py`
- Modify: `scripts/exhaustive_api_oracle.py`
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/fixtures/real_projects/commons-text.json`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Produces: `run_constant_oracle(old_jar, consumer_artifacts, api_rows, javap="javap") -> ConstantOracleLedger`.
- Produces one Oracle row for every constant-field API identity, including tool versions, command digest, artifact SHA, `ConstantValue` result, and exact field-link occurrences.

- [ ] **Step 1: Write failing Oracle independence and closed-set tests**

Patch analyzer collectors to wrong values and prove Oracle output is unchanged. Reject missing, duplicate, extra, wrong descriptor, wrong SHA, and stronger analyzer conclusions.

- [ ] **Step 2: Verify Oracle RED**

Run: `python3 -m unittest -v tests.test_constant_impact_oracle`

Expected: import failure because the independent Oracle is absent.

- [ ] **Step 3: Implement javap-verbose and independent bytecode Oracle**

Use `javap -verbose -p` for old-field `ConstantValue` and a separate constant-pool scanner for consumer `Fieldref` identities. Do not import analyzer extraction or adjudication functions.

- [ ] **Step 4: Integrate Commons Text full-API reconciliation**

Extend the pinned Commons Text case so every dynamically discovered constant change is included. Require analyzer/Oracle identity equality and exact compile/runtime conclusions.

- [ ] **Step 5: Add Oracle fault mutations**

Inject wrong constant value, removed field link, extra field link, wrong descriptor, and stale SHA. Require each mutation to trigger a distinct blocking signal.

- [ ] **Step 6: Verify and commit**

Run: `python3 -m unittest -q tests.test_constant_impact_oracle tests.test_exhaustive_api_oracle tests.test_real_project_regression tests.test_fault_injection`

Commit: `test: add independent constant impact oracle`

### Task 4: Spring AOP and Security Activation Collectors

**Files:**
- Modify: `scripts/framework_adapters.py`
- Modify: `scripts/step5_evidence_model.py`
- Modify: `scripts/step5_evidence_ingestion.py`
- Create: `tests/test_spring_activation_closure.py`
- Modify: `tests/test_framework_adapters.py`
- Modify: `tests/fixtures/topologies/manifest.json`

**Interfaces:**
- Produces: `collect_spring_aop_activation(runtime_catalog, business_inventory) -> CollectorBatch`.
- Produces: `collect_spring_security_filter_activation(runtime_catalog, business_inventory) -> CollectorBatch`.
- Evidence types: `spring_aop_activation`, `spring_security_filter_activation`, and typed incomplete failures.

- [ ] **Step 1: Write failing positive/negative/incomplete topology tests**

Compile active `@Aspect` advice, packaged unregistered aspect, unsupported pointcut, registered security filter chain, packaged filter without chain registration, and conditional registration without resolved condition.

- [ ] **Step 2: Verify activation RED**

Run: `python3 -m unittest -v tests.test_spring_activation_closure`

Expected: active cases remain uncertain and collectors are missing.

- [ ] **Step 3: Implement artifact-bound AOP collection**

Require application ownership, final-artifact SHA, runtime-visible registration annotations, exact advice identity, and a conservative supported pointcut match. Unsupported or partial evidence emits an incomplete record.

- [ ] **Step 4: Implement artifact-bound security chain collection**

Require exact filter class, bean or chain registration, chain membership/order, and application entry activation. Never promote an unregistered packaged filter.

- [ ] **Step 5: Ingest typed activation without ordinary-edge coercion**

Map composite proofs into the existing evidence model and single adjudicator. Assert evidence type and activation identity survive JSON and CSV output.

- [ ] **Step 6: Verify topology closure and commit**

Run: `python3 -m unittest -q tests.test_spring_activation_closure tests.test_framework_adapters tests.test_step5_evidence_model tests.test_step5_evidence_ingestion tests.test_topology_coverage`

Commit: `feat: close spring activation evidence paths`

### Task 5: Mall Real-Project Oracle and TODO Closure

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/fixtures/real_projects/mall-full-artifact-discovery.json`
- Create: `tests/fixtures/real_projects/mall-framework-activation-oracle.csv`
- Modify: `tests/test_real_project_regression.py`
- Modify: `tests/fixtures/capability_families.json`
- Modify: `TODO.md`

**Interfaces:**
- Consumes both constant and framework evidence records.
- Produces exact per-API Mall activation reconciliation and capability closure evidence.

- [ ] **Step 1: Write failing Mall closed-world tests**

Require every discovered Hutool target API and every framework activation path to match the independent artifact/resource Oracle. Add inactive and incomplete controls.

- [ ] **Step 2: Verify real-project RED**

Run: `python3 -m unittest -v tests.test_real_project_regression.RealProjectRegressionTest.test_mall_framework_activation_closed_world`

- [ ] **Step 3: Implement the independent Mall activation Oracle**

Use final-artifact entries, runtime-visible annotations, Spring resources, exact advice/filter identities, and artifact SHA. Do not consume analyzer edge output.

- [ ] **Step 4: Register capability evidence and remove only completed TODO entries**

Add positive, negative, incomplete, mutation, and cross-project guards to `capability_families.json`. Delete both TODO sections only after all focused commands pass.

- [ ] **Step 5: Run Program 1 release verification and commit**

Run: `python3 scripts/quality_gate.py --profile release --real-case guard --continue-on-failure --json-out /tmp/jua-program1-release.json`

Expected: `release_allowed`, zero mandatory skips, zero blocking signals, Commons Text and Mall guards passed.

Commit: `feat: complete production evidence closure`
