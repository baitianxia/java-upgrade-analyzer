# Real Project Testing V3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make real-project testing independently verify every relevant final-artifact call edge, require declared topology coverage, fix same-coordinate bridge analysis, and enforce performance without reducing scope.

**Architecture:** Add a standalone `javap`-based edge oracle that emits canonical edge identities from a SHA-verified final artifact, then reconcile it with an analyzer edge ledger before deriving API conclusions. Extend the real-project runner with topology, edge-truth, asset, performance, and fixture-debt gates; keep final-artifact bytecode as the only deterministic runtime authority. Fix Step5 same-coordinate handling by retaining executable internal edges as bridge evidence while excluding the target jar from direct-consumer classification.

**Tech Stack:** Python 3 standard library, `javap`, ZIP/JAR parsing, CSV/JSON evidence, `dataclasses`, `unittest`, Maven-built executable JAR fixtures.

## Global Constraints

- Deterministic runtime claims use only a SHA-256-verified `current_final_artifact`.
- `target/classes`, IDE output, source compilation directories, and stale jars never contribute runtime truth.
- Every selected API and every authoritative edge involved in its runtime path is reconciled without sampling.
- Oracle and analyzer ledgers share only a serialized schema, never parsed class structures or matching results.
- Project selection is driven by uncovered topology IDs; size alone is not coverage.
- Performance optimizations may cache immutable artifact-hash results but may not reduce APIs, classes, topologies, or oracle edges.
- Any blocking asset, API, topology, edge, conclusion, performance, or fixture-debt signal makes the case fail.

---

### Task 1: Canonical Edge Contract

**Files:**
- Create: `scripts/edge_truth.py`
- Create: `tests/test_edge_truth.py`

**Interfaces:**
- Produces: `EdgeIdentity` frozen dataclass with artifact SHA, caller/callee owner/member/descriptor, and opcode family.
- Produces: `canonical_edge_identity(row: dict) -> str`
- Produces: `reconcile_edges(analyzer_rows: list[dict], oracle_rows: list[dict]) -> dict`
- Produces verdicts: `correct`, `missing`, `extra`, `identity_mismatch`, `provenance_invalid`, `oracle_conflict`.

- [ ] **Step 1: Write failing identity and reconciliation tests**

```python
def test_descriptor_and_opcode_are_part_of_edge_identity(self):
    base = edge("a" * 64, "p.C", "call", "()V", "q.Api", "run", "()V", "invokevirtual")
    overload = {**base, "callee_descriptor": "(I)V"}
    interface = {**base, "opcode_family": "invokeinterface"}
    self.assertNotEqual(edge_truth.canonical_edge_identity(base), edge_truth.canonical_edge_identity(overload))
    self.assertNotEqual(edge_truth.canonical_edge_identity(base), edge_truth.canonical_edge_identity(interface))

def test_reconciliation_reports_missing_extra_and_invalid_provenance(self):
    result = edge_truth.reconcile_edges([valid_edge("run")], [valid_edge("other"), invalid_edge()])
    self.assertEqual(result["verdict_counts"]["missing"], 1)
    self.assertEqual(result["verdict_counts"]["extra"], 1)
    self.assertEqual(result["verdict_counts"]["provenance_invalid"], 1)
    self.assertTrue(result["blocking"])
```

- [ ] **Step 2: Verify the contract tests fail**

Run: `python3 -m unittest tests.test_edge_truth -v`

Expected: `ImportError` because `scripts/edge_truth.py` does not exist.

- [ ] **Step 3: Implement immutable identity and multiset reconciliation**

```python
@dataclass(frozen=True, order=True)
class EdgeIdentity:
    artifact_sha256: str
    caller_owner: str
    caller_member: str
    caller_descriptor: str
    callee_owner: str
    callee_member: str
    callee_descriptor: str
    opcode_family: str

def canonical_edge_identity(row: dict) -> str:
    return "|".join(str(row.get(field) or "").strip() for field in EDGE_IDENTITY_FIELDS)
```

Validate 64-character lowercase SHA-256, artifact entry, authority, authority version, and procedure before comparing counters. Pair same caller/callee names with differing descriptors/opcodes as `identity_mismatch`; leave unrelated identities as `missing` or `extra`.

- [ ] **Step 4: Run focused tests**

Run: `python3 -m unittest tests.test_edge_truth -v`

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/edge_truth.py tests/test_edge_truth.py
git commit -m "Add canonical edge truth contract"
```

### Task 2: Independent Final-Artifact Edge Oracle

**Files:**
- Create: `scripts/final_artifact_edge_oracle.py`
- Create: `tests/test_final_artifact_edge_oracle.py`
- Test fixture: construct temporary executable JARs inside the test; do not read repository build output.

**Interfaces:**
- Consumes: `EdgeIdentity`, `canonical_edge_identity` from Task 1.
- Produces: `scan_final_artifact(artifact: Path, javap: str = "javap") -> dict`
- Produces result keys: `artifact_sha256`, `class_count`, `parse_seconds`, `edges`, `failures`, `complete`.
- Produces edge provenance: final-artifact entry, SHA-256, `authority="jdk-javap"`, Java version, and procedure version.

- [ ] **Step 1: Write failing oracle tests for all JVM instruction families**

Compile temporary Java sources with `javac`, package business classes under `BOOT-INF/classes` and dependency classes in nested JARs, then assert exact edges for `invokevirtual`, `invokeinterface`, `invokestatic`, `invokespecial`/`<init>`, field get/put, and `invokedynamic`. Assert malformed or partially parsed artifacts return `complete=False` and never silently omit failures.

- [ ] **Step 2: Verify tests fail**

Run: `python3 -m unittest tests.test_final_artifact_edge_oracle -v`

Expected: module import failure.

- [ ] **Step 3: Implement final-artifact enumeration and `javap -c -p -s` parsing**

Use `zipfile` to extract only class entries from the final artifact and nested runtime JARs into a temporary directory. Parse method headers, descriptors, instruction offsets, opcode families, and constant-pool comments into canonical rows. Treat declarations as context only; emit an edge only for an executable instruction.

```python
INVOKE_OPCODES = {"invokevirtual", "invokeinterface", "invokestatic", "invokespecial", "invokedynamic"}
FIELD_OPCODES = {"getfield", "putfield", "getstatic", "putstatic"}

def scan_final_artifact(artifact: Path, javap: str = "javap") -> dict:
    digest = sha256_file(artifact)
    entries = enumerate_packaged_classes(artifact)
    rows, failures = parse_entries_with_javap(entries, digest, javap)
    return {"artifact_sha256": digest, "class_count": len(entries), "edges": rows,
            "failures": failures, "complete": not failures}
```

- [ ] **Step 4: Verify oracle completeness and independence**

Run: `python3 -m unittest tests.test_final_artifact_edge_oracle tests.test_edge_truth -v`

Expected: all tests pass; no import from `confidence_weighted_tracer`, `business_bytecode_graph`, or analyzer parser modules.

- [ ] **Step 5: Commit**

```bash
git add scripts/final_artifact_edge_oracle.py tests/test_final_artifact_edge_oracle.py
git commit -m "Add independent final artifact edge oracle"
```

### Task 3: Preserve Same-Coordinate Executable Bridges

**Files:**
- Modify: `scripts/confidence_weighted_tracer.py`
- Modify: `tests/test_step5_key_matching.py`

**Interfaces:**
- Produces: same-coordinate bytecode hits with `edge_role="internal_bridge"`.
- Preserves: `has_external_direct_consumer(target_coord, candidate)` as the only direct-consumer coordinate gate.
- Requires: internal bridge reachability only after reverse traversal reaches final-artifact business evidence.

- [ ] **Step 1: Add failing regressions for all three scan paths**

Create one test each for single-target scan, constant-pool batch fast path, and `javap` batch slow path. Each supplies a real executable same-coordinate call and asserts it is retained as `internal_bridge`; add a declaration-only negative test and a target-jar-without-business-entry negative test.

- [ ] **Step 2: Verify the new tests fail for `SOURCE_BYTECODE_EDGE_CONFLICT` or missing hits**

Run: `python3 -m unittest tests.test_step5_key_matching.Step5KeyMatchingTests.test_same_coordinate_single_scan_retains_internal_bridge tests.test_step5_key_matching.Step5KeyMatchingTests.test_same_coordinate_batch_fast_path_retains_internal_bridge tests.test_step5_key_matching.Step5KeyMatchingTests.test_same_coordinate_batch_javap_retains_internal_bridge -v`

- [ ] **Step 3: Replace coordinate skips with instruction-aware edge roles**

Remove the three `coord == api_row["coord"]: continue` branches. At each emitted executable match assign:

```python
same_coord = coord == str(api_row.get("coord") or "").strip()
hit["edge_role"] = "internal_bridge" if same_coord else "external_consumer"
hit["direct_consumer"] = not same_coord
```

Keep declaration records out of hit creation and require `_has_exact_business_bytecode_target` or reverse business traversal before an internal bridge can yield `reachable`.

- [ ] **Step 4: Run focused and Step5 tests**

Run: `python3 -m unittest tests.test_step5_key_matching -v`

Expected: all Step5 key-matching tests pass, including declaration-only negatives.

- [ ] **Step 5: Commit**

```bash
git add scripts/confidence_weighted_tracer.py tests/test_step5_key_matching.py
git commit -m "Preserve same coordinate bytecode bridges"
```

### Task 4: Analyzer Edge Ledger

**Files:**
- Modify: `scripts/confidence_weighted_tracer.py`
- Modify: `tests/test_step5_key_matching.py`
- Modify: `docs/user/outputs.md`

**Interfaces:**
- Produces: `evidence/call_chain/analyzer_edges.csv`.
- Produces rows matching Task 1 canonical schema plus `api_identity`, `edge_role`, evidence path, and procedure version.
- Produces summary metrics: `analyzer_edge_count`, `duplicate_edge_count`, `edge_ledger_complete`.

- [ ] **Step 1: Write failing ledger tests**

Assert overloads and constructors remain distinct, same-coordinate bridges are present, duplicate discoveries collapse by canonical identity, and every row references the verified final-artifact SHA. Assert missing artifact provenance sets `edge_ledger_complete=false`.

- [ ] **Step 2: Verify tests fail because no ledger is written**

Run: `python3 -m unittest tests.test_step5_key_matching.Step5KeyMatchingTests.test_writes_complete_analyzer_edge_ledger -v`

- [ ] **Step 3: Add one ledger collector at executable-edge creation points**

```python
def record_analyzer_edge(graph, api_row, edge):
    row = normalize_analyzer_edge(api_row, edge)
    graph.analyzer_edges[canonical_edge_identity(row)] = row
```

Write stable sorted CSV rows after Step5 completes. Do not reconstruct edges from human-readable alert chains.

- [ ] **Step 4: Verify ledger tests and output documentation**

Run: `python3 -m unittest tests.test_step5_key_matching tests.test_user_visible_output_contract -v`

Expected: tests pass and documented fields match the CSV header.

- [ ] **Step 5: Commit**

```bash
git add scripts/confidence_weighted_tracer.py tests/test_step5_key_matching.py docs/user/outputs.md
git commit -m "Emit canonical analyzer edge ledger"
```

### Task 5: Topology Classification and Coverage Gate

**Files:**
- Create: `scripts/topology_coverage.py`
- Create: `tests/test_topology_coverage.py`
- Create: `tests/fixtures/topologies/src/` Java source set covering the stable topology IDs.
- Create: `tests/fixtures/topologies/manifest.json` with expected canonical edges and topology IDs.
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Produces: `classify_topologies(edges: list[dict], artifact_layout: dict) -> set[str]`.
- Adds `required_topologies: tuple[str, ...]` to `RealProjectCase`.
- Produces: `topology_coverage.json`, `topology_coverage.csv`, and blocking `topology_coverage_gap`.

- [ ] **Step 1: Write failing topology matrix tests**

Compile the topology Java source set into a temporary executable JAR and scan it with the independent oracle. Assert stable classifications for direct business, same/cross-JAR bridges, same-coordinate multimodule, overload, constructor, interface/virtual/static dispatch, field access, invokedynamic, source-bytecode agreement, and true conflict. Add packaged service registration and framework registration manifests for SPI, reflection, and proxy cases; these IDs require explicit authoritative registration evidence and must not be inferred from names.

- [ ] **Step 2: Verify tests fail**

Run: `python3 -m unittest tests.test_topology_coverage tests.test_real_project_regression -v`

- [ ] **Step 3: Implement classification and gate integration**

```python
def compute_topology_coverage(required: tuple[str, ...], observed: set[str]) -> dict:
    missing = sorted(set(required) - observed)
    return {"required": sorted(set(required)), "observed": sorted(observed),
            "missing": missing, "complete": not missing}
```

Emit one P1 blocking signal containing all missing stable IDs. A discovery project with no newly observed topology remains valid only as an existing guard; it is not eligible as the next discovery target.

- [ ] **Step 4: Run focused tests**

Run: `python3 -m unittest tests.test_topology_coverage tests.test_real_project_regression -v`

Expected: all topology and runner tests pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/topology_coverage.py tests/test_topology_coverage.py tests/fixtures/topologies/src tests/fixtures/topologies/manifest.json scripts/real_project_regression.py tests/test_real_project_regression.py
git commit -m "Gate real projects on topology coverage"
```

### Task 6: Exhaustive Edge-Truth Gate and Strict Conflict Semantics

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `scripts/quality_signal_audit.py`
- Modify: `tests/test_real_project_regression.py`
- Modify: `tests/test_quality_signal_audit.py`

**Interfaces:**
- Consumes: analyzer ledger from Task 4 and oracle scan from Task 2.
- Produces: `oracle_edges.csv`, `edge_reconciliation.csv`, edge counts in `performance_envelope.json`.
- Produces blocking signals: `edge_truth_failure`, `oracle_incomplete`, `source_bytecode_conflict_invalid`.

- [ ] **Step 1: Write failing runner and release-audit tests**

Assert a matching API conclusion still fails when an intermediate edge is missing. Assert an extra edge is blocking when it creates false reachability, invalid provenance always blocks, and `SOURCE_BYTECODE_EDGE_CONFLICT` is rejected unless both normalized source and final-artifact edge identities are present with known source revision provenance.

- [ ] **Step 2: Verify tests fail**

Run: `python3 -m unittest tests.test_real_project_regression tests.test_quality_signal_audit -v`

- [ ] **Step 3: Run the oracle and reconcile every selected API edge**

Filter oracle edges by exact API owner/member/descriptor, recursively retain caller edges needed to reach a business class or authoritative runtime boundary, then call `reconcile_edges`. Write all rows, not samples. Include bounded samples only inside the quality signal message.

- [ ] **Step 4: Verify runner status and release rejection**

Run: `python3 -m unittest tests.test_real_project_regression tests.test_quality_signal_audit tests.test_quality_gate -v`

Expected: any edge-truth blocker yields case status `failed` and release rejection.

- [ ] **Step 5: Commit**

```bash
git add scripts/real_project_regression.py scripts/quality_signal_audit.py tests/test_real_project_regression.py tests/test_quality_signal_audit.py
git commit -m "Gate real project results on exhaustive edge truth"
```

### Task 7: Performance and Duplicate-Scan Budget

**Files:**
- Modify: `scripts/confidence_weighted_tracer.py`
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`
- Modify: `tests/test_step5_key_matching.py`

**Interfaces:**
- Extends `performance_envelope.json` with artifact bytes, class counts, oracle/analyzer edges, parse/reconcile rates, cache hits, `javap` fallbacks, and duplicate scans.
- Adds case budgets: `max_duplicate_class_scans`, `max_seconds_per_100k_edges`, `min_classes_per_second`.

- [ ] **Step 1: Add failing normalized-budget tests**

Assert the target runtime JAR may be parsed once for internal edges but is never counted as a direct consumer scan; repeated artifact SHA scans hit the immutable cache. Assert scope counters are identical before and after caching and budget failures emit blocking `performance_regression`.

- [ ] **Step 2: Verify tests fail on duplicate target-JAR scans**

Run: `python3 -m unittest tests.test_real_project_regression tests.test_step5_key_matching -v`

- [ ] **Step 3: Add artifact-hash parse cache and metrics**

```python
cache_key = (artifact_sha256, parser_procedure_version, target_jdk)
if cache_key in edge_cache:
    metrics["artifact_cache_hits"] += 1
    return edge_cache[cache_key]
```

Count each class-entry parse. Keep direct-consumer classification separate from internal-edge parsing so the target JAR contributes bridge edges exactly once without producing false direct impact.

- [ ] **Step 4: Verify unchanged scope and improved duplicate-scan count**

Run: `python3 -m unittest tests.test_real_project_regression tests.test_step5_key_matching -v`

Expected: all tests pass; API, class, topology, and edge counts remain unchanged between cached and uncached runs.

- [ ] **Step 5: Commit**

```bash
git add scripts/confidence_weighted_tracer.py scripts/real_project_regression.py tests/test_real_project_regression.py tests/test_step5_key_matching.py
git commit -m "Gate exhaustive analysis performance"
```

### Task 8: `gs-multi-module` Real-Project Guard and Fixture Debt

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`
- Create: `tests/fixtures/real_projects/gs-multi-module.json`
- Modify: `docs/developer/quality.md`

**Interfaces:**
- Adds case: `gs-multi-module` with required topologies `business_to_same_jar_bridge` and `same_coord_multimodule`.
- Expected chain: `DemoApplication.home -> MyService.message -> ServiceProperties.getMessage()`.
- Produces: fixture-debt rows for all P0/P1 findings with state `fixed`, `planned`, or `waived_until`.

- [ ] **Step 1: Add failing guard-contract test**

Load the pinned fixture manifest and assert its Git revision, artifact SHA-256, exact API descriptor, required topology IDs, two exact canonical edges, and expected `reachable` conclusion. Assert `SOURCE_BYTECODE_EDGE_CONFLICT` fails this guard.

- [ ] **Step 2: Verify the guard fails with the current analyzer behavior**

Run: `python3 -m unittest tests.test_real_project_regression.RealProjectRegressionTests.test_gs_multi_module_same_coordinate_guard -v`

Expected before Task 3 changes: failure showing missing same-coordinate bridge; after Task 3, the fixture contract test passes.

- [ ] **Step 3: Integrate the pinned final artifact and fixture-debt gate**

Require the artifact SHA from the manifest before execution. Run exhaustive API and edge oracles, write all V3 outputs, and mark the original same-coordinate finding `fixed` only when the guard passes. Missing state or expired waiver emits blocking `fixture_debt`.

- [ ] **Step 4: Run the real guard and inspect all seven gates**

Run: `python3 scripts/real_project_regression.py --case gs-multi-module`

Expected: `asset`, `api_coverage`, `topology_coverage`, `edge_truth`, `conclusion`, `performance`, and `fixture_debt` all pass; the API is `reachable`; both canonical edges reconcile as `correct`.

- [ ] **Step 5: Commit**

```bash
git add scripts/real_project_regression.py tests/test_real_project_regression.py tests/fixtures/real_projects/gs-multi-module.json docs/developer/quality.md
git commit -m "Add same coordinate real project guard"
```

### Task 9: Full Verification and Discovery Rotation

**Files:**
- Modify: `docs/developer/quality.md`
- Modify only if failures reveal V3 defects: files owned by Tasks 1-8 with a new failing regression first.

**Interfaces:**
- Consumes all V3 outputs and gates.
- Produces a topology gap list used to select the next real project; does not select by repository size.

- [ ] **Step 1: Run focused V3 verification**

```bash
python3 -m unittest tests.test_edge_truth tests.test_final_artifact_edge_oracle tests.test_topology_coverage tests.test_real_project_regression tests.test_quality_signal_audit tests.test_quality_gate -v
```

Expected: all focused tests pass.

- [ ] **Step 2: Run the complete repository suite**

Run: `python3 -m unittest discover -s tests -p 'test_*.py'`

Expected: all tests pass with zero errors and failures.

- [ ] **Step 3: Re-run one converged project and one discovery project**

Run the `gs-multi-module` guard plus the configured discovery case. Compare every selected API and every retained authoritative edge. Record topology IDs newly covered by the discovery case and list remaining IDs.

- [ ] **Step 4: Enforce rotation decision**

If the discovery project adds neither a new topology ID nor a P0/P1 finding, demote it to a guard and select the next project specifically for the first uncovered topology ID. Document the pinned revision, final-artifact SHA, exact commands, measured envelope, and remaining coverage gaps.

- [ ] **Step 5: Commit final verification documentation**

```bash
git add docs/developer/quality.md
git commit -m "Document V3 verification and project rotation"
```
