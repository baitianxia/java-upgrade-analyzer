# Operational and Performance Assurance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect execution failures, nondeterminism, superlinear work, platform defects, and public Claude Code workflow drift before release.

**Architecture:** Typed execution faults exercise real subprocess and artifact boundaries. Determinism and complexity gates consume normalized production reports, while portable GitHub jobs and a clean-checkout harness validate the public skill contract independently of developer state.

**Tech Stack:** Python 3.12 standard library, unittest, subprocess, resource/process metrics, GitHub Actions, JDK 11/17/21, Maven.

## Global Constraints

- Faults must resolve to one explicit fail-closed state and reason code.
- Performance results are invalid when correctness or scope differs.
- Platform exclusions must be explicit; mandatory jobs cannot silently skip.
- The Claude Code contract tests `SKILL.md` commands and artifacts, not an LLM.
- No new third-party package is installed.

---

### Task 1: Full-Pipeline Execution Fault Registry

**Files:**
- Create: `scripts/execution_faults.py`
- Create: `tests/test_execution_faults.py`
- Modify: `scripts/fault_injection.py`
- Modify: `scripts/quality_gate.py`

**Interfaces:**
- Produces: `ExecutionFaultSpec(id, boundary, trigger, expected_status, expected_reason)`.
- Produces: copied-input fault contexts for timeout, exit, truncation, partial write, artifact replacement, permission, encoding, interruption, cancellation, and cache races.

- [ ] Write one failing integration test for each registered fault and assert its exact fail-closed reason.
- [ ] Verify malformed or partial output never becomes an empty successful result.
- [ ] Implement faults only in test orchestration; production modules receive ordinary failing dependencies/files.
- [ ] Emit immutable before/after digests and cleanup status for every run.
- [ ] Add mandatory execution-fault detection to release profile.
- [ ] Run focused tests and commit `test: inject full pipeline execution faults`.

### Task 2: Full-Pipeline Determinism Gate

**Files:**
- Create: `scripts/determinism_gate.py`
- Create: `tests/test_determinism_gate.py`
- Modify: `scripts/quality_gate.py`

**Interfaces:**
- Produces: `normalize_semantic_report(report_dir) -> bytes`.
- Produces: `run_determinism_matrix(case, hash_seeds, workers, cache_modes, order_modes) -> DeterminismReport`.

- [ ] Write failing tests where path order, set iteration, or worker completion order changes a ledger.
- [ ] Define retained semantic fields and rejected undocumented volatility.
- [ ] Run production analysis under `PYTHONHASHSEED=1,7,101`, workers `1,2,4`, cold/warm cache, and normal/reversed enumeration.
- [ ] Compare byte-identical normalized API, edge, completeness, and reason-code ledgers.
- [ ] Persist the first structured difference and reproduction command.
- [ ] Add core matrix to quick and full matrix to release; commit `test: enforce full pipeline determinism`.

### Task 3: Complexity and Resource Scaling Gate

**Files:**
- Create: `scripts/complexity_gate.py`
- Create: `tests/test_complexity_gate.py`
- Modify: `scripts/step1_observability.py`
- Modify: `scripts/s4_jar_compare.py`
- Modify: `scripts/confidence_weighted_tracer.py`
- Modify: `scripts/real_project_regression.py`

**Interfaces:**
- Produces per-stage metrics: elapsed, peak RSS, temporary bytes, archive scans, parsed classes, javap calls, cache hits, and per-API latency.
- Produces: `evaluate_scale_tiers(tiers, absolute_budgets, ratio_budgets) -> ComplexityVerdict`.

- [ ] Write failing synthetic tiers at 1x, 2x, and 4x APIs/classes/JARs and inject duplicate scanning.
- [ ] Assert correctness identities and scope counters are equal to each tier's truth manifest before evaluating performance.
- [ ] Instrument missing Step1/4/5 counters without adding per-item subprocesses.
- [ ] Enforce declared absolute and adjacent-tier ratio budgets from a versioned fixture file.
- [ ] Report the duplicate work key and responsible stage on failure.
- [ ] Run synthetic and pinned real-project performance gates; commit `perf: enforce stage complexity budgets`.

### Task 4: Portable Platform Contract

**Files:**
- Create: `.github/workflows/platform-contract.yml`
- Create: `tests/test_platform_contract.py`
- Modify: `tests/test_subprocess_encoding.py`
- Modify: `scripts/compat.py`

**Interfaces:**
- Matrix: Ubuntu, macOS, Windows; JDK 11/17/21 where supported by the job.
- Covers path separators, Unicode/non-UTF8 output, process timeout termination, file locking, long paths, and command argument preservation.

- [ ] Write workflow contract tests requiring all platforms, explicit Python/JDK/Maven setup, timeout, JSON evidence upload, and no `continue-on-error` on mandatory jobs.
- [ ] Write platform-neutral subprocess/path tests before changing compatibility code.
- [ ] Implement only generalized compatibility fixes exposed by those tests.
- [ ] Run local contract tests and validate workflow YAML structurally.
- [ ] Commit `ci: add portable platform contract matrix`.

### Task 5: Clean Claude Code Skill Contract

**Files:**
- Create: `scripts/claude_skill_contract.py`
- Create: `tests/test_claude_skill_contract.py`
- Modify: `SKILL.md` only when a tested command or path is incorrect.
- Modify: `.github/workflows/release-regression.yml`

**Interfaces:**
- Produces: `run_skill_contract(repo_root, fixture_project, workspace) -> SkillContractReport`.
- Consumes only public commands, prerequisites, checkpoints, and output paths parsed from `SKILL.md`.

- [ ] Write failing tests for undocumented dependency, stale command, wrong output path, missing checkpoint, failed resume, and dependence on repository-local report state.
- [ ] Materialize a clean repository copy and fixture project without user files or caches.
- [ ] Execute documented commands as argument arrays, verify checkpoint behavior, outputs, restart, and rerun idempotence.
- [ ] Fail when implementation requires an input not declared by the public skill contract.
- [ ] Add clean contract to release CI and upload its evidence.
- [ ] Commit `test: validate clean claude code skill workflow`.

### Task 6: Final Cross-Program Closure

**Files:**
- Modify: `tests/fixtures/capability_families.json`
- Modify: `scripts/test_round_retrospective.py`
- Modify: `TODO.md`
- Modify: `docs/developer/quality.md`

**Interfaces:**
- Consumes all three program reports.
- Produces one final release decision and capability closure ledger.

- [ ] Register execution faults, determinism variants, scale budgets, platform jobs, and skill-contract evidence.
- [ ] Run all focused suites and the complete unittest suite.
- [ ] Run the release gate against all mandatory real-project guards with no skips.
- [ ] Verify all required production mutants are killed and Oracle boundaries are clean.
- [ ] Remove only TODO entries whose executable evidence maps are complete.
- [ ] Request independent code review and resolve every Important/Critical finding.
- [ ] Run a fresh final release gate after the final fix and commit `test: complete quality capability closure`.
