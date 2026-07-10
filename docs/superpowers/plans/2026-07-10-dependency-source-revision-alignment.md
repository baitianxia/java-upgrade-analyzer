# Dependency Source Revision Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Step5 parse dependency source only from the Step4-confirmed current-version commit and only for classes packaged in the same current runtime JAR.

**Architecture:** Add a focused alignment module that converts user source mappings into immutable detached-worktree snapshots using Step4 ref evidence and produces per-coordinate JAR class allowlists. Step5 consumes only aligned mappings, filters dependency source methods before graph indexing, records alignment evidence, and falls back to current-artifact bytecode without ever using an unverified local branch.

**Tech Stack:** Python 3 standard library, Git detached worktrees, ZIP/JAR class indexing, existing `unittest` suite.

## Global Constraints

- Current final-artifact JAR/class data remains the primary fact source.
- Never run checkout, switch, reset, clean, or stash in a user dependency repository.
- Never fall back to the original local dependency source mapping after alignment failure.
- A source class may enter the graph only if the same coordinate's current runtime JAR contains that class.
- Preserve shared class-resolution indexes and all FQCN/simple-key safety guards.
- Do not add a user-mandatory report file; alignment JSON is supporting evidence.

---

### Task 1: Isolated Revision Alignment Module

**Files:**
- Create: `scripts/dependency_source_alignment.py`
- Create: `tests/test_dependency_source_alignment.py`

**Interfaces:**
- Consumes: `report_dir`, raw `coord=path` mappings, runtime catalog `by_coord`, and Step4 `git_ref_matches.json`.
- Produces: `align_dependency_source_mappings(...) -> dict` with `mappings`, `allowed_classes_by_coord`, and `records`.

- [ ] **Step 1: Write failing tests for ref selection and workspace preservation**

Create a temporary Git repository with branches `wrong-local` and `jar-version`. Put `WrongOnly.java` on the checked-out branch and `RightOnly.java` on `jar-version`, leave an uncommitted marker, and write Step4 evidence selecting `jar-version`. Assert the result mapping points inside `.runtime/source_snapshots`, contains `RightOnly.java`, excludes `WrongOnly.java`, and leaves branch, HEAD, and porcelain output unchanged.

- [ ] **Step 2: Write failing tests for missing, conflicting, and invalid refs**

Cover no Step4 record, two different current refs for one coordinate, missing ref, repository mismatch, and path-escaping `module_rel_path`. Assert each produces no mapping, a `rejected` record, a stable reason code, and never returns the original source path.

- [ ] **Step 3: Write a failing snapshot-reuse test**

Run alignment twice for the same commit. Assert both results use the same detached worktree path and the second record contains `snapshot_reused: true`.

- [ ] **Step 4: Implement ref evidence loading and normalization**

Implement helpers:

```python
def load_step4_current_ref_records(report_dir): ...
def normalize_mapping(mapping): ...
def resolve_unique_ref_record(coord, records): ...
def repository_fingerprint(repo_path): ...
```

Read both direct fields and `item['meta']`; normalize coordinates to group/artifact for catalog matching but reject multiple distinct repo/ref/module triples.

- [ ] **Step 5: Implement detached worktree materialization**

Implement:

```python
def materialize_detached_snapshot(report_dir, coord, repo_path, ref, module_rel_path): ...
```

Resolve `ref^{commit}`, create `.runtime/source_snapshots/<slug>/<commit[:12]>` with `git worktree add --detach`, reuse only when HEAD matches, and reject invalid existing directories without deleting them.

- [ ] **Step 6: Implement runtime JAR class indexing and source-root discovery**

Implement:

```python
def index_jar_classes(jar_path): ...
def discover_standard_source_dirs(snapshot_module_root): ...
```

Exclude metadata classes and return exact FQCN sets per coordinate. Require a readable JAR and at least one production Java/Kotlin source root.

- [ ] **Step 7: Implement orchestration and evidence writing**

`align_dependency_source_mappings` must preserve repository fingerprints, reject failures, return only snapshot mappings, and write `evidence/call_chain/dependency_source_alignment.json` with JSON-safe class counts rather than class lists.

- [ ] **Step 8: Run Task 1 tests**

Run:

```bash
python3 -m unittest tests.test_dependency_source_alignment -v
```

Expected: all alignment tests pass.

### Task 2: Filter Dependency Source Classes Before Graph Indexing

**Files:**
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Modify: `tests/test_step5_key_matching.py`

**Interfaces:**
- Consumes: `allowed_classes_by_coord: dict[str, set[str]]` from Task 1.
- Produces: `build_enhanced_source_graph(..., allowed_dependency_classes_by_coord=None)` with absent dependency classes excluded before methods and edges are indexed.

- [ ] **Step 1: Write a failing same-coordinate packaged-class filter test**

Create two dependency source classes under one root, allow only one FQCN, and assert only the packaged class's methods and reverse edges exist.

- [ ] **Step 2: Write a failing cross-coordinate same-name test**

Create `com.alpha.StringUtils` for coordinate A and `com.beta.StringUtils` for coordinate B. Give each coordinate only its own JAR class allowlist and assert neither allowlist can validate the other coordinate's class.

- [ ] **Step 3: Add filtering helpers**

Implement:

```python
def source_class_fqcn_candidates(entry): ...
def filter_dependency_source_entry(entry, allowed_dependency_classes_by_coord): ...
```

Normalize nested source classes (`Outer.Inner`) against classfile names (`Outer$Inner`) and filter both `methods` and `declared_types`. Business entries remain unchanged.

- [ ] **Step 4: Thread the allowlist through source collection and graph building**

Add the optional argument to `_collect_source_file_entries` and `build_enhanced_source_graph`. Apply filtering immediately after file analysis and before adding the entry to analysis cache, methods, class metadata, or initializer discovery.

- [ ] **Step 5: Preserve shared-index and FQCN guards**

Extend the existing memory regression to run with a dependency class allowlist and assert every retained method still shares the same `known_classes_by_simple` object. Re-run the existing simple-key anti-stitch tests.

- [ ] **Step 6: Run focused graph tests**

Run the new class-filter tests plus:

```bash
python3 -m unittest \
  tests.test_step5_key_matching.Step5KeyMatchingTest.test_build_enhanced_source_graph_shares_class_resolution_indexes_across_methods \
  tests.test_step5_key_matching.Step5KeyMatchingTest.test_trace_does_not_stitch_business_call_to_dependency_method_by_simple_name \
  tests.test_step5_key_matching.Step5KeyMatchingTest.test_dependency_source_graph_does_not_index_simple_method_keys -v
```

Expected: all pass.

### Task 3: Integrate Alignment into Step5 and Safe Degradation

**Files:**
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Modify: `tests/test_step5_key_matching.py`
- Modify: `docs/developer/step5-design.md`
- Modify: `docs/user/outputs.md`

**Interfaces:**
- Consumes: `align_dependency_source_mappings` result.
- Produces: Step5 graphs built only from aligned snapshots, plus explicit alignment failures in existing missing-input/not-analyzed explanations.

- [ ] **Step 1: Write a failing Step5 orchestration test**

Mock alignment to return one snapshot mapping and one rejection. Assert business pre-analysis is unchanged, the full dependency graph receives only the snapshot mapping and allowlist, and the original local path is absent from all graph roots.

- [ ] **Step 2: Write a failing no-silent-fallback test**

Mock alignment to reject every dependency source while runtime JAR fallback is available. Assert Step5 continues with JAR evidence and never passes the raw source path to graph construction or framework adapters. Without sufficient JAR evidence, assert the existing interaction/not-analyzed path includes the human reason “依赖源码版本无法与当前运行时 JAR 对齐”.

- [ ] **Step 3: Integrate alignment after runtime-catalog filtering**

Call alignment immediately after `filter_dependency_source_mappings_for_runtime`. Replace `dependency_source_mappings` with result mappings, retain the allowlist, and append rejected records to bridge-discovery unresolved inputs. Do not mutate the raw mappings.

- [ ] **Step 4: Pass allowlists into full graph construction**

Business graph receives no dependency allowlist. Dependency graph receives `allowed_dependency_classes_by_coord`. Keep bytecode catalog, business bytecode merge, and packaged dependency tracing unchanged.

- [ ] **Step 5: Prevent auxiliary source analyzers from using rejected mappings**

Framework and indirect analyzers receive only aligned snapshot roots. Document that graph class filtering is authoritative; source-derived framework evidence must be discarded when its owner class is absent from the same-coordinate allowlist.

- [ ] **Step 6: Align diagnostics and documentation**

Add alignment counts and evidence path to graph stats/debug output. Update docs to state that dependency source is version-pinned auxiliary evidence and that alignment failure causes JAR-only analysis rather than local-branch fallback.

- [ ] **Step 7: Run Step5-focused tests**

Run:

```bash
python3 -m unittest tests.test_dependency_source_alignment tests.test_step5_key_matching -v
```

Expected: all tests pass.

### Task 4: Regression and Real Multi-Branch Git Validation

**Files:**
- Verify: `scripts/dependency_source_alignment.py`
- Verify: `scripts/s5_call_chain_engine_integrated.py`
- Verify: `tests/test_dependency_source_alignment.py`
- Verify: `tests/test_step5_key_matching.py`

**Interfaces:**
- Consumes: completed implementation.
- Produces: fresh evidence that results use the selected ref, stay within JAR scope, and retain existing accuracy/performance protections.

- [ ] **Step 1: Run syntax and diff checks**

```bash
python3 -m py_compile scripts/dependency_source_alignment.py scripts/s5_call_chain_engine_integrated.py
git diff --check -- scripts/dependency_source_alignment.py scripts/s5_call_chain_engine_integrated.py tests/test_dependency_source_alignment.py tests/test_step5_key_matching.py docs/developer/step5-design.md docs/user/outputs.md
```

Expected: exit 0.

- [ ] **Step 2: Run complete automated regression**

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Expected: zero failures and errors.

- [ ] **Step 3: Run a real local multi-branch repository scenario**

Create an actual temporary Git dependency repository, compile the selected-ref source into a JAR, leave the repository checked out on a conflicting branch with uncommitted content, generate real Step4 ref evidence, and run Step5. Verify the call graph contains selected-ref methods only, excludes the conflicting branch and unjarred module, and repository state is byte-for-byte unchanged.

- [ ] **Step 4: Audit accuracy invariants**

Verify:

- every dependency source graph root is under `.runtime/source_snapshots`;
- every retained dependency source class exists in the same-coordinate JAR;
- no rejected original path appears in graph/debug evidence;
- `commons-lang` and `commons-lang3` same-name APIs remain isolated;
- all methods share the class-resolution map;
- JAR-only generated methods remain discoverable;
- conclusion counts for an unchanged existing Dubbo fixture do not change when no dependency source mapping is supplied.

- [ ] **Step 5: Review final scope**

Inspect the final diff and confirm no checkout/reset/clean/stash command was introduced and unrelated existing working-tree changes were preserved.
