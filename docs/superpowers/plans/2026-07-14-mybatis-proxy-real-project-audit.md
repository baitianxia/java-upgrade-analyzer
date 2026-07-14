# MyBatis Proxy Real-Project Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an exhaustive, independently verified real-project guard for MyBatis annotation and XML mapper proxies, prove the guard detects damaged evidence, and fix any general Step5 defects exposed by the audit.

**Architecture:** Two executable samples from one pinned official repository form the target system. A new independent Oracle inventories physical bytecode calls, classfile annotations, mapper XML bindings, framework dispatch, artifact provenance, and runtime activation without consuming analyzer conclusions. The existing topology and real-project gates consume typed semantic references, while final API statuses continue through the shared Step5 evidence policy.

**Tech Stack:** Python 3 standard library, `unittest`, ZIP/classfile parsing, safe XML parsing, JDK `javap`, Maven, Spring Boot Fat Jars, MyBatis 3.5.19.

## Global Constraints

- Do not install a runtime dependency or non-Codex plugin.
- Pin Git revision `92431b4231a59a87a9408658d4b1740892a4a0ab` and exact artifact SHA-256 values.
- Inspect final executable Jars; source and `target/classes` are not runtime truth.
- Declare the selected API denominator before reading analyzer output; no sampling.
- Keep semantic proxy/configuration links separate from physical JVM call edges.
- Missing required evidence blocks negative conclusions.
- Write a failing focused test before each production fix.
- Do not modify the external checkout to make a test pass.
- Existing report schemas and real-project guards remain compatible.

---

### Task 1: Pin, Build, and Execute Both Real Artifacts

**Files:**
- Create: `tests/fixtures/real_projects/mybatis-sample-annotation.json`
- Create: `tests/fixtures/real_projects/mybatis-sample-xml.json`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Consumes: checkout `/private/tmp/jua-real-project-mybatis-spring-boot-starter-3`.
- Produces: two fixture manifests with revision, artifact path, artifact SHA, expected runtime output, and explicit source/resource inventory.

- [ ] **Step 1: Write failing fixture-contract tests**

```python
def test_mybatis_sample_fixtures_pin_two_distinct_final_artifacts(self):
    annotation = load_fixture("mybatis-sample-annotation.json")
    xml = load_fixture("mybatis-sample-xml.json")
    self.assertEqual(PINNED_MYBATIS_REVISION, annotation["git_revision"])
    self.assertEqual(PINNED_MYBATIS_REVISION, xml["git_revision"])
    self.assertNotEqual(annotation["final_artifact_sha256"], xml["final_artifact_sha256"])
    self.assertEqual("reviewed", annotation["ground_truth_status"])
    self.assertEqual("reviewed", xml["ground_truth_status"])
```

- [ ] **Step 2: Verify the fixture tests fail**

Run: `python3 -m unittest tests.test_real_project_regression.RealProjectRegressionTest.test_mybatis_sample_fixtures_pin_two_distinct_final_artifacts -v`

Expected: `FileNotFoundError` for the new fixture.

- [ ] **Step 3: Build the pinned samples**

Run from the target checkout:

```bash
mvn -q -DskipTests -pl mybatis-spring-boot-samples/mybatis-spring-boot-sample-annotation,mybatis-spring-boot-samples/mybatis-spring-boot-sample-xml -am package
```

Record SHA-256 for:

```text
mybatis-spring-boot-samples/mybatis-spring-boot-sample-annotation/target/mybatis-spring-boot-sample-annotation-4.0.2-SNAPSHOT.jar
mybatis-spring-boot-samples/mybatis-spring-boot-sample-xml/target/mybatis-spring-boot-sample-xml-4.0.2-SNAPSHOT.jar
```

- [ ] **Step 4: Execute both artifacts**

Run `java -jar` for each artifact. Require exit code zero. Require the annotation
sample output to contain `San Francisco,CA,US`; require the XML sample output to
contain both `San Francisco,CA,US` and `Conrad Treasury Place`.

- [ ] **Step 5: Write pinned manifests and make the tests pass**

Each manifest records exact revision, artifact SHA/path, runtime command/result,
`BOOT-INF/classes` application entries, mapper class entries, mapper resources,
and an empty `unverified_apis` list.

- [ ] **Step 6: Commit the asset baseline**

```bash
git add tests/fixtures/real_projects/mybatis-sample-annotation.json tests/fixtures/real_projects/mybatis-sample-xml.json tests/test_real_project_regression.py
git commit -m "test: pin MyBatis proxy audit artifacts"
```

### Task 2: Independent Mapper Evidence Oracle

**Files:**
- Create: `scripts/mybatis_mapper_oracle.py`
- Create: `tests/test_mybatis_mapper_oracle.py`

**Interfaces:**
- Produces: `inspect_mybatis_artifact(path: Path, timeout_seconds: float) -> dict`.
- Produces: `mapper_contracts`, `statement_bindings`, `physical_edges`, `proxy_dispatch_links`, `failures`, `metrics`, and `complete`.
- Consumes: final Fat Jar bytes only; it must not import `confidence_weighted_tracer`, `framework_adapters`, or analyzer result readers.

- [ ] **Step 1: Write failing annotation and XML inventory tests**

```python
def test_oracle_requires_packaged_mapper_registration_and_binding(self):
    result = inspect_mybatis_artifact(self.fixture_jar, timeout_seconds=5.0)
    self.assertEqual(
        [("sample.mybatis.xml.mapper.HotelMapper", "selectByCityId", "(I)Lsample/mybatis/xml/domain/Hotel;")],
        result["mapper_contracts"],
    )
    self.assertEqual(
        [("sample.mybatis.xml.mapper.HotelMapper", "selectByCityId")],
        result["statement_bindings"],
    )
    self.assertTrue(result["complete"])
```

- [ ] **Step 2: Verify the Oracle tests fail**

Run: `python3 -m unittest tests.test_mybatis_mapper_oracle -v`

Expected: import failure because `mybatis_mapper_oracle.py` does not exist.

- [ ] **Step 3: Implement archive and annotation inventory**

Read nested `BOOT-INF/lib/mybatis-3.5.19.jar` and
`BOOT-INF/lib/mybatis-spring-4.1.0.jar` in memory. Parse classfile constant-pool and
annotation attributes sufficiently to identify exact `@Mapper`, `@Select`, and
method descriptors. Record parser failures instead of swallowing exceptions.

- [ ] **Step 4: Implement safe mapper-resource inventory**

Parse `mybatis-config.xml` and each declared mapper XML through `safe_xml.py`.
Require an exact namespace/interface match and exact statement id/method match.
Treat duplicate namespace/id pairs as an ambiguity failure.

- [ ] **Step 5: Implement independent framework dispatch proof**

Use `javap -c -p -s` on packaged `MapperProxy`, `MapperProxy$PlainMethodInvoker`,
and `MapperMethod`. Prove exact calls ending at:

```text
org.apache.ibatis.binding.MapperMethod.execute(Lorg/apache/ibatis/session/SqlSession;[Ljava/lang/Object;)Ljava/lang/Object;
org.apache.ibatis.session.SqlSession.selectOne(Ljava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;
```

Emit semantic links with `evidence_authority=final-artifact-javap-plus-mapper-registration`.

- [ ] **Step 6: Add completeness and metrics tests**

Assert timeout, malformed classfile, missing nested framework Jar, malformed XML,
duplicate statement, and unresolved mapper resource all produce named failures and
`complete=False`. Assert class/resource counts, elapsed time, `javap_tasks`, and
duplicate scan count are present.

- [ ] **Step 7: Run Oracle tests and commit**

Run: `python3 -m unittest tests.test_mybatis_mapper_oracle -v`

Expected: all tests pass.

```bash
git add scripts/mybatis_mapper_oracle.py tests/test_mybatis_mapper_oracle.py
git commit -m "test: add independent MyBatis mapper oracle"
```

### Task 3: Exhaustive API Denominator and Real-Project Cases

**Files:**
- Create: `tests/fixtures/real_projects/mybatis-sample-annotation-changed-apis.csv`
- Create: `tests/fixtures/real_projects/mybatis-sample-xml-changed-apis.csv`
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Produces: guard cases `mybatis-sample-annotation` and `mybatis-sample-xml`.
- Consumes: `inspect_mybatis_artifact()` and the two pinned manifests.

- [ ] **Step 1: Declare the API rows before analyzer execution**

The annotation denominator contains the invoked
`sample.mybatis.annotation.mapper.CityMapper.findByState(String)` mapper contract
and the selected framework dispatch APIs. The XML denominator contains
`sample.mybatis.xml.mapper.HotelMapper.selectByCityId(int)`, direct
`org.apache.ibatis.session.SqlSession.selectOne(String,Object)`, and the selected
framework dispatch APIs. Every row includes exact descriptor, symbol kind,
coordinate, expected status, and required evidence authority.

- [ ] **Step 2: Write failing denominator tests**

```python
def test_mybatis_denominators_equal_independent_oracle_targets(self):
    for case_name in ("mybatis-sample-annotation", "mybatis-sample-xml"):
        declared = selected_targets(read_changed_apis(CASES[case_name].default_changed_apis))
        oracle = selected_targets(load_mapper_oracle_fixture(case_name))
        self.assertEqual(oracle, declared)
```

- [ ] **Step 3: Register both guard cases**

Require topologies `business_direct`, `framework_callback`, and
`mybatis_mapper_proxy`; require valid Git revision/artifact SHA and reviewed ground
truth. Do not embed project-name rules in topology extraction.

- [ ] **Step 4: Reconcile semantic references without fabricating edges**

Extend the existing semantic-reference reconciliation to accept mapper links only
when artifact SHA, mapper contract, statement binding, proxy dispatch, and runtime
activation all match. Physical edge reconciliation remains unchanged.

- [ ] **Step 5: Run fixture and runner contract tests**

Run: `python3 -m unittest tests.test_real_project_regression -v`

Expected: all tests pass.

### Task 4: Fault-Injection Gate Validation

**Files:**
- Modify: `tests/test_mybatis_mapper_oracle.py`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Consumes: temporary mutated copies of fixture Fat Jars or Oracle records.
- Produces: deterministic guard failures with stable reason codes.

- [ ] **Step 1: Add a ZIP mutation helper in tests**

The helper copies all entries except an explicitly removed entry or replaces one
resource payload. It never writes to the pinned checkout or fixture artifact.

- [ ] **Step 2: Verify missing and mismatched XML failures**

Remove `CityMapper.xml`, then separately change its namespace and statement id.
Assert `MAPPER_RESOURCE_MISSING`, `MAPPER_NAMESPACE_MISMATCH`, and
`MAPPER_STATEMENT_UNRESOLVED` respectively, with `complete=False`.

- [ ] **Step 3: Verify annotation and dispatch evidence failures**

Remove the mapper annotation evidence record and the proxy dispatch semantic link
from separate Oracle copies. Assert topology, edge-truth, and conclusion gates fail;
none may pass from expected-status data alone.

- [ ] **Step 4: Verify timeout blocks negative conclusions**

Inject `ORACLE_TIMEOUT` and assert the API is `not_analyzed`, never
`not_found_in_static_analysis`.

- [ ] **Step 5: Run mutation tests repeatedly**

Run the mutation test class three times. Require identical failure codes and no
order-dependent output.

### Task 5: First Analyzer Audit and Model-Based Fixes

**Files:**
- Modify only the Step5 module responsible for each demonstrated defect.
- Modify the focused test file for each defect.

**Interfaces:**
- Consumes: the two guard cases and independent Oracle evidence.
- Produces: exact per-API agreement with no unverified or extra selected target.

- [ ] **Step 1: Run both guards before production changes**

```bash
python3 scripts/real_project_regression.py --case mybatis-sample-annotation --report-root /private/tmp/jua-mybatis-audit/annotation --json-out /private/tmp/jua-mybatis-audit/annotation.json
python3 scripts/real_project_regression.py --case mybatis-sample-xml --report-root /private/tmp/jua-mybatis-audit/xml --json-out /private/tmp/jua-mybatis-audit/xml.json
```

Record every disagreement by API, status, path, edge, evidence authority, and
completeness. A zero-defect result is accepted only if all deliberate mutations
already failed as required.

- [ ] **Step 2: Reproduce each disagreement with a focused RED test**

The focused fixture contains only the smallest mapper contract, registration, and
dispatch evidence needed to reproduce the real failure. Verify it fails for the
same reason as the real project.

- [ ] **Step 3: Fix shared architecture, not the project case**

Add typed semantic evidence or policy handling in `step5_evidence_model.py`,
`framework_adapters.py`, `topology_coverage.py`, or the responsible collector.
Do not branch on repository, module, or sample names.

- [ ] **Step 4: Re-run focused tests after every fix**

Require the new regression, existing evidence-model tests, and affected Step5 tests
to pass before re-running the real artifact.

- [ ] **Step 5: Re-run both exhaustive audits**

Require all gates to pass, `unverified_apis=[]`, no extra selected target, and
exact independent evidence for every declared row.

### Task 6: Performance, Full Verification, and Delivery

**Files:**
- Modify: fixture performance baselines only after reviewed measurements.

**Interfaces:**
- Produces: complete verification evidence, clean commit history, and pushed branch.

- [ ] **Step 1: Enforce performance budgets**

Require no duplicate artifact scans, bounded `javap_tasks`, positive class/resource
parse rates, and elapsed time within the existing absolute budget. Record the
reviewed baseline and reject a regression above 25%.

- [ ] **Step 2: Run focused suites**

```bash
python3 -m unittest tests.test_mybatis_mapper_oracle tests.test_step5_evidence_model tests.test_step5_key_matching tests.test_real_project_regression tests.test_topology_coverage -q
```

- [ ] **Step 3: Run all permanent real-project guards**

Run every reviewed guard case, including `gs-multi-module`,
`gs-messaging-rabbitmq`, `gs-managing-transactions`, `dubbo-spring6-security`, and
both MyBatis cases.

- [ ] **Step 4: Run the full suite and static checks**

```bash
python3 -m unittest discover -s tests -q
python3 -m py_compile scripts/mybatis_mapper_oracle.py scripts/real_project_regression.py scripts/topology_coverage.py scripts/step5_evidence_model.py
git diff --check
```

Expected: zero failures and zero formatting errors.

- [ ] **Step 5: Commit and push**

Verify the external checkout is clean and generated reports are absent from this
repository. Commit the implementation and push
`codex/step5-bytecode-index-optimization` only after all evidence gates pass.
