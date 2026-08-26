# Step5 Cold-Run Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce first-run Step5 wall time by sharing SHA-bound artifact inventory, class facts and `javap` work across consumers without changing any analysis result.

**Architecture:** Add a per-run immutable `Step5ArtifactFactStore` after the runtime catalog is built. Migrate consumers one at a time behind parity checks: the store shares ZIP inventories and single-flight class facts, while existing analyzers retain their decision logic and remain the fallback whenever shared and legacy facts differ.

**Tech Stack:** Python 3.12, `zipfile`, frozen dataclasses, `threading.Condition`, existing classfile parsers, `unittest`, Step5 result fingerprints and real-project regression harness.

## Global Constraints

- The current final artifact remains the only dependency fact source.
- Do not reduce JARs, classes, APIs, framework adapters, call depth or low-confidence candidates.
- API status, reason code, path order, evidence and coverage must remain byte-for-byte equivalent after volatile fields are removed.
- Parse failures remain explicit failures; they never become empty reference sets.
- Peak RSS must not increase and optimized cold-run median wall time must be lower.
- Each independently testable change is committed separately.

---

### Task 1: Establish cold-run parse-count and result baselines

**Files:**
- Create: `tests/test_step5_artifact_fact_store.py`
- Modify: `scripts/real_project_regression.py`

**Interfaces:**
- Produces: `step5_result_contract(report_dir: Path) -> dict` containing canonical status/path/evidence data and `cold_run_metrics(report_dir: Path) -> dict` reading Step5 timing metrics.

- [ ] **Step 1: Write failing contract tests**

Create two reports with different absolute roots and telemetry but identical alerts/summary/query-index facts; assert equal contracts. Change path order, evidence type and coverage independently; assert each changes the contract. Assert an absent Step5 report raises `FileNotFoundError`.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `python3 -m unittest tests.test_step5_artifact_fact_store.Step5ColdRunContractTest`

Expected: import failure for `step5_result_contract`.

- [ ] **Step 3: Implement the contract helpers**

Reuse `_canonicalize_step5_result_value` but return the canonical payload before hashing:

```python
def step5_result_contract(report_dir):
    payload = _canonical_step5_result_payload(report_dir)
    if not payload:
        raise FileNotFoundError(report_dir)
    return payload

def cold_run_metrics(report_dir):
    path = Path(report_dir) / ".runtime/observability/step5_timing.csv"
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return {
            f"{row['section']}.{row['metric']}": row["value"]
            for row in csv.DictReader(handle)
        }
```

- [ ] **Step 4: Record baseline cases**

Run three fresh report roots for `gs-multi-module` and the largest locally available guard case. Save only JSON results under `/private/tmp`; do not commit generated reports.

- [ ] **Step 5: Verify and commit**

Run: `python3 -m unittest tests.test_step5_artifact_fact_store tests.test_real_project_regression`

Commit:

```bash
git add tests/test_step5_artifact_fact_store.py scripts/real_project_regression.py
git commit -m "test: establish step5 cold run parity baseline"
```

### Task 2: Build immutable artifact inventory with Multi-Release selection

**Files:**
- Create: `scripts/step5_artifact_fact_store.py`
- Test: `tests/test_step5_artifact_fact_store.py`

**Interfaces:**
- Produces:
  - `ArtifactIdentity(coord, path, sha256, artifact_entry, target_jdk)`
  - `ClassLocation(logical_name, binary_name, physical_entry, multi_release_version)`
  - `ArtifactInventory(identity, classes, resources, failure)`
  - `Step5ArtifactFactStore.from_catalog(catalog)`
  - `inventory(coord) -> ArtifactInventory`

- [ ] **Step 1: Write failing inventory tests**

Cover SHA mismatch, corrupt ZIP, ordinary JAR, Spring Boot business JAR, and `META-INF/versions/11` selection for target JDK 8/11/17. Assert class order matches existing `_runtime_class_variants` semantics and repeated calls return the identical immutable object.

- [ ] **Step 2: Verify RED**

Run: `python3 -m unittest tests.test_step5_artifact_fact_store.ArtifactInventoryTest`

Expected: module import failure.

- [ ] **Step 3: Implement frozen inventory types and one-time ZIP enumeration**

Use frozen dataclasses and a lock-protected single-flight cache. Verify the file SHA before and after inventory construction. Store entry names only, not class bytes:

```python
@dataclass(frozen=True)
class ArtifactInventory:
    identity: ArtifactIdentity
    classes: tuple[ClassLocation, ...]
    resources: tuple[str, ...]
    failure: str = ""
```

Failure inventories are cached with their reason so later consumers cannot reinterpret the failure as an empty JAR.

- [ ] **Step 4: Verify exact ordering and failure behavior**

Run inventory tests plus `tests.test_step5_key_matching` Multi-Release cases.

- [ ] **Step 5: Commit**

```bash
git add scripts/step5_artifact_fact_store.py tests/test_step5_artifact_fact_store.py
git commit -m "feat: share immutable step5 artifact inventories"
```

### Task 3: Add single-flight class facts and canonical javap profiles

**Files:**
- Modify: `scripts/step5_artifact_fact_store.py`
- Test: `tests/test_step5_artifact_fact_store.py`

**Interfaces:**
- Produces:
  - `FactOutcome(status, value, reason, parser)`
  - `class_bytes(coord, location) -> FactOutcome`
  - `class_fact(coord, location, namespace, producer) -> FactOutcome`
  - `javap_fact(coord, location, profile, producer) -> FactOutcome`
  - `metrics() -> dict[str, int | float]`

- [ ] **Step 1: Write concurrency and failure tests**

Start eight threads requesting the same class fact; assert the producer executes once and all callers receive the same immutable outcome. Repeat with a producer exception and assert one explicit failure is shared. Assert different artifact SHA, target JDK, entry, namespace or profile never collide.

- [ ] **Step 2: Verify RED**

Run: `python3 -m unittest tests.test_step5_artifact_fact_store.SingleFlightFactTest`

- [ ] **Step 3: Implement single-flight without swallowing exceptions**

Use a `Condition` per key. Convert producer exceptions into `FactOutcome(status="failed", reason="Type: message")`, increment failure metrics and notify all waiters in `finally`. Values must be tuples, frozen dataclasses, strings, bytes or recursively frozen mappings.

- [ ] **Step 4: Add bounded retention**

Class bytes are returned but never cached. Header/constant-pool facts and canonical javap text are cached. Executable edge facts are cached only while a registered consumer lease is active; `release_consumer(name)` drops facts whose remaining lease count is zero.

- [ ] **Step 5: Verify and commit**

Run the store tests under normal execution and `PYTHONHASHSEED=123` to prove deterministic ordering.

```bash
git add scripts/step5_artifact_fact_store.py tests/test_step5_artifact_fact_store.py
git commit -m "feat: single flight step5 class facts"
```

### Task 4: Migrate business bytecode collection behind strict parity

**Files:**
- Modify: `scripts/business_bytecode_graph.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Test: `tests/test_step5_artifact_fact_store.py`
- Test: `tests/test_step5_key_matching.py`

**Interfaces:**
- `collect_business_bytecode_batch(..., fact_store=None, verify_parity=True)`
- Produces parity metrics: `business_bytecode_parity_checks`, `business_bytecode_parity_mismatches`, `business_bytecode_fact_hits`.

- [ ] **Step 1: Write failing parity tests**

Build fixtures containing ordinary calls, fields, constructors, Lambda/method references, reflection fallback, switch instructions, inner classes and malformed class bytes. Assert shared and legacy collectors produce identical ordered `CollectorBatch` values and failures.

- [ ] **Step 2: Verify RED**

Run the new parity tests and confirm the collector rejects `fact_store`.

- [ ] **Step 3: Implement shared collection**

Read inventory and class bytes from the store. Reuse `parse_classfile_calls`; on `None`, request canonical `javap -v -c -p -s` text through `javap_fact` and parse with `parse_javap_calls`. Preserve sorted physical-entry order and all existing evidence fields.

- [ ] **Step 4: Add strict shadow comparison and fallback**

For test/guard mode, execute both collectors and compare normalized batches. For production, compare on deterministic canary classes plus all fallback/error classes; any mismatch sets `fact_store_parity_mismatch`, uses the complete legacy batch and records the differing class identities. No mismatch can be hidden.

- [ ] **Step 5: Verify and commit**

Run business bytecode, evidence ingestion, Lambda, reflection, Multi-Release and Step5 key suites.

```bash
git add scripts/business_bytecode_graph.py scripts/s5_call_chain_engine_integrated.py tests/test_step5_artifact_fact_store.py tests/test_step5_key_matching.py
git commit -m "perf: share business bytecode class facts"
```

### Task 5: Share framework inventory and javap without changing adapter rules

**Files:**
- Modify: `scripts/framework_adapters.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Test: `tests/test_framework_adapters.py`
- Test: `tests/test_step5_artifact_fact_store.py`

**Interfaces:**
- `run_framework_adapters(..., fact_store=None)`
- Internal helpers: `_artifact_inventory(entry, fact_store)` and `_shared_javap(entry, owner, profile, fact_store)`.

- [ ] **Step 1: Write failing adapter parity tests**

Cover MyBatis proxy, Spring transaction, Spring Data repository, runtime Spring registration and message-listener data flow. Instrument ZIP/Javap calls and assert shared mode returns identical serialized batches while reducing repeated inventory/Javap producer calls.

- [ ] **Step 2: Verify RED**

Run the selected framework tests and confirm the new argument/helper is absent.

- [ ] **Step 3: Migrate common reads only**

Replace repeated `namelist()`/membership scans with store inventory and replace direct `subprocess.run(javap...)` with `_shared_javap`. Keep every adapter's regex/AST/XML interpretation, edge construction, error message and tuple ordering unchanged.

- [ ] **Step 4: Preserve unsupported access paths**

If an adapter requires temporary extracted class files or a profile not covered by canonical output, keep its legacy command until a dedicated equivalence test proves migration. Record it as `framework_unshared_javap`; do not force reuse.

- [ ] **Step 5: Verify and commit**

Run all framework adapter and evidence ingestion tests and compare serialized adapter JSON byte-for-byte after path normalization.

```bash
git add scripts/framework_adapters.py scripts/s5_call_chain_engine_integrated.py tests/test_framework_adapters.py tests/test_step5_artifact_fact_store.py
git commit -m "perf: share framework artifact facts"
```

### Task 6: Reuse inventories and class summaries in runtime dependency tracing

**Files:**
- Modify: `scripts/confidence_weighted_tracer.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Test: `tests/test_step5_key_matching.py`
- Test: `tests/test_step5_artifact_fact_store.py`

**Interfaces:**
- Graph receives `step5_artifact_fact_store`.
- `_build_runtime_dependency_member_candidate_index` consumes store inventories and namespaced constant-pool facts.
- Existing tracer cache APIs remain available for isolated tests.

- [ ] **Step 1: Write failing exact-index tests**

Create two artifacts with same class names but different SHA, Multi-Release variants, overloads, reflection strings and one corrupt class. Assert the shared candidate index equals the legacy index and corrupt input remains a failure.

- [ ] **Step 2: Verify RED**

Run candidate-index and runtime expansion tests before implementation.

- [ ] **Step 3: Connect the existing constant-pool parser to the store**

Use inventory locations instead of reopening each JAR to enumerate names. Store `_parse_classfile_constant_pool_summary` results under a versioned namespace. Preserve `direct_by_owner_member`, string indexes, reflection IDs, task order and completeness rules.

- [ ] **Step 4: Route javap fallbacks through the store**

Adapt `_load_runtime_dependency_class_references` so canonical `javap` text comes from the shared single-flight profile, then run the unchanged `_parse_javap_bytecode_references` parser. Keep analyzer ledger failures and timeout semantics.

- [ ] **Step 5: Verify and commit**

Run all Step5 key matching, runtime bytecode, topology, query and output-contract tests.

```bash
git add scripts/confidence_weighted_tracer.py scripts/s5_call_chain_engine_integrated.py tests/test_step5_key_matching.py tests/test_step5_artifact_fact_store.py
git commit -m "perf: reuse artifact facts during runtime tracing"
```

### Task 7: Observability, cold-run benchmark and release gate

**Files:**
- Modify: `scripts/step5_artifact_fact_store.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Modify: `docs/developer/step5-design.md`
- Modify: `docs/user/outputs.md`
- Test: `tests/test_step5_artifact_fact_store.py`

**Interfaces:**
- Adds `artifact_facts` scalar metrics to `.runtime/observability/step5_timing.csv`.

- [ ] **Step 1: Test observability fields**

Assert inventory builds/hits, class reads/bytes, fact hits/misses, javap requests/starts/shared hits/failures, parity checks/mismatches and consumer reads are emitted without retaining graph references.

- [ ] **Step 2: Run focused and smoke suites**

```bash
python3 -m unittest tests.test_step5_artifact_fact_store tests.test_framework_adapters tests.test_step5_evidence_ingestion tests.test_step5_key_matching
python3 scripts/smoke_regression.py --group core
python3 scripts/smoke_regression.py --group step5
```

- [ ] **Step 3: Run three fresh cold-start comparisons**

Use distinct empty report roots for baseline and optimized revisions. Compare total and phase medians, peak RSS, parse counts and canonical contracts. Reject the optimization if optimized median increases, peak RSS increases, any contract differs or parity mismatch is nonzero.

- [ ] **Step 4: Run real-project audit and complete suite**

Run `gs-multi-module`, a framework-heavy guard case and the largest available local project. Inspect every status bucket and all reported chains, then run:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

- [ ] **Step 5: Document verified metrics and commit**

Document metric meanings, not machine-specific promised durations.

```bash
git add scripts/step5_artifact_fact_store.py scripts/s5_call_chain_engine_integrated.py docs/developer/step5-design.md docs/user/outputs.md tests/test_step5_artifact_fact_store.py
git commit -m "docs: document step5 cold run fact metrics"
```

- [ ] **Step 6: Final repository audit**

Run `git diff --check`, `git status --short`, inspect all commits and confirm the existing untracked ZIP was not modified.
