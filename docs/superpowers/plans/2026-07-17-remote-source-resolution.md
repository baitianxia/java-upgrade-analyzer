# Remote-first source resolution implementation plan

> Execute this plan in the current session. Keep final artifacts as the only fact source; source remains auxiliary evidence.

**Goal:** Every pipeline path that needs source resolves a live remote ref to an immutable commit first. Local refs/worktrees are usable only after explicit user confirmation, with dirty state separately acknowledged.

**Architecture:** Add one shared remote-ref resolver and make Step1, Step4 and Step5 consume its structured result. The resolver queries live remotes with bounded commands, fetches only the selected ref, fixes a commit, and never changes the user's checked-out branch. Existing artifact/JAR selection remains unchanged.

**Implementation language:** Python 3, `git` subprocesses through `scripts.compat.run_cmd`, `unittest` regression tests.

---

## Task 1: Shared live-remote resolver

**Files:**
- Create: `scripts/remote_source_refs.py`
- Create: `tests/test_remote_source_refs.py`

1. Add failing tests for explicit `origin/release`, unqualified unique remote, equal-commit multi-remote, divergent multi-remote, remote failure, fetch failure, and local fallback gating.
2. Implement parsing for `git remote` and `git ls-remote --heads --tags`, excluding peeled tag records.
3. Resolve candidates by full remote/ref or unqualified branch/tag name. Never consult local branches during remote resolution.
4. Materialize the selected remote object with a bounded targeted fetch and verify `<sha>^{commit}`.
5. Add a separate local resolver that is callable only with `allow_local_source=True`; reject dirty repositories unless `allow_dirty_local_source=True`.
6. Return stable structured states and provenance: requested ref, remote, remote ref, commit, candidates, failures, resolution mode and query time.
7. Run `python3 -m unittest tests.test_remote_source_refs -v`.

## Task 2: Step1 remote-first branch selection and checkpoints

**Files:**
- Modify: `scripts/step1_ref_resolution.py`
- Modify: `scripts/run_step.py`
- Modify: `tests/test_step1_ref_resolution.py`
- Modify: `tests/test_run_step_main_state.py`

1. Add failing tests proving a same-name local branch cannot override a live remote branch.
2. Add tests for ambiguous remote refs and remote-unavailable states producing a checkpoint rather than local fallback.
3. Add structured response fields for per-side local fallback and dirty-source confirmation.
4. Replace Step1 resolution with the shared resolver and preserve remote provenance in the resolved-ref record.
5. Ensure direct final-artifact inputs with complete coordinates do not query source.
6. Run the focused Step1 and orchestration tests.

## Task 3: Step1 missing-coordinate source supplement

**Files:**
- Modify: `scripts/s1_dep_diff.py`
- Modify: `tests/test_step1_packaged_deps.py`

1. Add failing tests for missing coordinates using the fixed remote commit snapshot.
2. Add tests proving remote errors stop before source build and do not silently use the current worktree.
3. Pass Step1's confirmed resolution/provenance into artifact dependency collection instead of resolving independently.
4. Keep dependency coordinates and dependency contents grounded in the final artifact; source may only fill missing coordinate metadata.
5. Run `python3 -m unittest tests.test_step1_packaged_deps -v` and the Step1 contract tests.

## Task 4: Step4 live remote inventory and immutable source diff

**Files:**
- Modify: `scripts/s4_jar_compare.py`
- Modify: `scripts/run_step.py`
- Modify: `tests/test_s4_jar_compare.py`
- Modify: `tests/test_run_step_main_state.py`

1. Add failing tests that stale `refs/remotes/*` are ignored in favor of live `ls-remote` results.
2. Add tests for multiple remotes, ambiguity, remote failures and user-confirmed local overrides.
3. Replace cached local remote-tracking discovery with shared live inventory.
4. Fetch and diff immutable remote commits; retain display refs separately for human-readable evidence.
5. Extend dependency ref overrides with explicit `allow_local_source` and `allow_dirty_local_source`; reject unconfirmed local refs.
6. Preserve the contract that JApiCmp and removed-symbol analysis use only Step1-retained old/current JARs.
7. Run focused Step4 and orchestration tests.

## Task 5: Step5 source-alignment enforcement

**Files:**
- Modify: `scripts/dependency_source_alignment.py`
- Modify: `scripts/s5_call_chain_engine_integrated.py`
- Modify: relevant `tests/test_step5_*.py`

1. Add failing tests that unconfirmed local source records and source/artifact mismatches cannot enter the deterministic source graph.
2. Accept only `remote_source_resolved` or explicitly `user_confirmed_local_source` records with a fixed commit.
3. Preserve bytecode edges as authoritative and record rejected source as a coverage gap, not a no-impact conclusion.
4. Verify remote detached snapshots are cleaned through `git worktree remove`/prune without touching the user's branch.
5. Run focused source-alignment and Step5 graph tests.

## Task 6: User-facing provenance and documentation

**Files:**
- Modify: `SKILL.md`
- Modify: `README.md`
- Modify: `RUNBOOK.md`
- Modify: Step6/report tests only if provenance is rendered there

1. Document the three-level evidence priority and the remote-unavailable confirmation flow in Claude Code terms.
2. Ensure user-facing checkpoint text says why remote source failed, which local commit is proposed, and that local source is auxiliary.
3. Surface remote/ref/commit or user-confirmed local provenance without exposing internal enum-only messages.
4. Verify docs do not tell users to run internal scripts manually.

## Task 7: Full verification and commit

1. Run all focused suites changed above.
2. Run `python3 -m unittest discover -s tests -p 'test_*.py'`.
3. Run the repository's core smoke/regression command documented in `RUNBOOK.md`.
4. Inspect `git diff --check`, `git status --short`, and the final diff for accidental changes to artifact authority.
5. Commit implementation and tests. Do not add generated ZIP files or runtime reports.

## Non-regression invariants

- No `git pull`, implicit checkout, merge or rebase.
- No source directory can add a module absent from the final artifact to a confirmed graph.
- Remote command failures and parser failures are explicit coverage gaps/checkpoints, never safe results.
- Local source is impossible without an explicit structured confirmation; dirty local source requires a second explicit confirmation.
- All external Git operations have timeouts and non-interactive behavior.
