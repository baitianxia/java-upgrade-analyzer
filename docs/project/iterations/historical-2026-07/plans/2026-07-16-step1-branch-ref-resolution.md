# Step1 Branch Ref Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 Step1 在同仓库双分支场景中优先固定并使用 base/current ref 补齐 Fat Jar 坐标，安全处理本地/远端候选、歧义确认和 source-only 输入。

**Architecture:** 新增独立的 Step1 ref 解析模块，负责无副作用地解析精确 ref、枚举本地与远端跟踪候选并按 commit 去歧义。`checkout_build` 由 `run_step.py` 在构建前完成解析与确认；`artifact_inputs` 先解析最终制品，只有某一侧坐标缺失时才由 `s1_dep_diff.py` 按需解析该侧 ref，并将 branch 置于 source directory 之前。Step1 进度与构建来源记录实际 ref、commit 和解析方式。

**Tech Stack:** Python 3、`unittest`、Git CLI、现有 checkpoint/interaction 协议、现有 Step1 observability JSONL/CSV。

## Global Constraints

- 最终制品仍是依赖版本与打包范围的事实来源；Git/Maven 只补充缺失坐标。
- 不执行隐式 `git fetch`，只读取已有 `refs/heads/*` 和 `refs/remotes/*`。
- 候选按 commit 去重；唯一 commit 才能自动采用，多个 commit 必须确认。
- 同时存在 branch/ref 与 source directory 时，branch/ref 优先。
- 只有 source directory 时必须确认当前 commit，确认前不得执行 Maven。
- 不得修改用户仓库当前分支、HEAD 或未提交内容，统一使用 detached worktree。
- 所有新增行为采用 TDD：先观察目标测试失败，再编写实现。

---

### Task 1: 建立无副作用的 Step1 ref 解析器

**Files:**
- Create: `scripts/step1_ref_resolution.py`
- Create: `tests/test_step1_ref_resolution.py`

**Interfaces:**
- Produces: `resolve_step1_ref(repo_dir: str | Path, requested_ref: str) -> dict`
- Result keys: `status`, `requested_ref`, `resolved_ref`, `resolved_commit`, `resolution_mode`, `candidates`, `fingerprint`
- `status` values: `resolved`, `ambiguous`, `not_found`
- `resolution_mode` values: `exact`, `unique_local`, `unique_remote`, `user_confirmed`, `unresolved`

- [ ] **Step 1: Write failing tests for exact and unique ref resolution**

```python
def test_exact_ref_resolves_to_commit(self):
    result = resolve_step1_ref(self.repo, "base-release")
    self.assertEqual(result["status"], "resolved")
    self.assertEqual(result["resolution_mode"], "exact")
    self.assertEqual(result["resolved_commit"], self.git("rev-parse", "base-release"))

def test_unique_remote_short_name_resolves_without_fetch(self):
    result = resolve_step1_ref(self.repo, "release-2.0.0")
    self.assertEqual(result["status"], "resolved")
    self.assertEqual(result["resolved_ref"], "origin/release-2.0.0")
    self.assertEqual(result["resolution_mode"], "unique_remote")
```

- [ ] **Step 2: Run tests and verify RED**

Run: `python3 -m unittest tests.test_step1_ref_resolution`

Expected: import failure for missing `step1_ref_resolution`.

- [ ] **Step 3: Implement ref enumeration, exact resolution and safe candidate scoring**

```python
def resolve_step1_ref(repo_dir, requested_ref):
    exact_commit = _resolve_commit(repo_dir, requested_ref)
    if exact_commit:
        return _resolved(requested_ref, requested_ref, exact_commit, "exact")
    candidates = _matching_candidates(_list_refs(repo_dir), requested_ref)
    commit_groups = _group_by_commit(candidates)
    if len(commit_groups) == 1:
        selected = _prefer_local_then_remote(next(iter(commit_groups.values())))
        return _resolved(
            requested_ref,
            selected["ref"],
            selected["commit"],
            "unique_local" if selected["kind"] == "local" else "unique_remote",
            candidates,
        )
    return _unresolved("ambiguous" if commit_groups else "not_found", requested_ref, candidates)
```

Candidate matching must accept exact short-name equivalence and version-boundary matches, reject matches inside longer numeric versions, exclude remote `HEAD`, and never invoke `fetch`.

- [ ] **Step 4: Add failing tests for ambiguity, same-commit deduplication and unsafe version substrings**

```python
def test_same_short_name_on_two_different_remote_commits_is_ambiguous(self):
    self.add_remote_ref("origin/release-2.0.0", self.base_commit)
    self.add_remote_ref("upstream/release-2.0.0", self.current_commit)
    result = resolve_step1_ref(self.repo, "release-2.0.0")
    self.assertEqual(result["status"], "ambiguous")
    self.assertEqual(len({item["commit"] for item in result["candidates"]}), 2)

def test_local_and_remote_refs_on_same_commit_are_not_ambiguous(self):
    self.add_local_ref("release-2.0.0", self.current_commit)
    self.add_remote_ref("origin/release-2.0.0", self.current_commit)
    result = resolve_step1_ref(self.repo, "release-2.0.0")
    self.assertEqual(result["status"], "resolved")
    self.assertEqual(result["resolved_commit"], self.current_commit)

def test_version_1_2_does_not_match_release_11_2_or_1_20(self):
    self.add_remote_ref("origin/release-11.2", self.base_commit)
    self.add_remote_ref("origin/release-1.20", self.current_commit)
    result = resolve_step1_ref(self.repo, "1.2")
    self.assertEqual(result["status"], "not_found")
```

- [ ] **Step 5: Run resolver tests and verify GREEN**

Run: `python3 -m unittest tests.test_step1_ref_resolution`

Expected: all resolver tests pass.

---

### Task 2: 在自动构建前解析、确认并持久化 ref

**Files:**
- Modify: `scripts/run_step.py`
- Modify: `tests/test_run_step_main_state.py`

**Interfaces:**
- Consumes: `resolve_step1_ref(...)`
- Produces: `resolve_step1_refs_for_execution(run_context, project_dir) -> (updated_context, interaction | None)`
- Adds Step1 context fields per side: `<side>_requested_ref`, `<side>_resolved_ref`, `<side>_resolved_commit`, `<side>_ref_resolution_mode`

- [ ] **Step 1: Write failing tests for preflight persistence and ambiguity interaction**

```python
def test_step1_preflight_persists_unique_remote_ref_and_commit(self):
    updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)
    self.assertIsNone(interaction)
    self.assertEqual(updated["current_resolved_ref"], "origin/release-2.0.0")
    self.assertTrue(updated["current_resolved_commit"])

def test_step1_preflight_stops_before_execution_for_ambiguous_remote_refs(self):
    updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)
    self.assertEqual(interaction["reason_code"], "ambiguous_step1_source_ref")
    self.assertEqual(interaction["kind"], "input_request")
    self.assertIn("current_branch", interaction["required_fields"])
```

- [ ] **Step 2: Run the targeted tests and verify RED**

Run: `python3 -m unittest tests.test_run_step_main_state.RunStepMainStateTest.test_step1_preflight_persists_unique_remote_ref_and_commit tests.test_run_step_main_state.RunStepMainStateTest.test_step1_preflight_stops_before_execution_for_ambiguous_remote_refs`

Expected: missing `resolve_step1_refs_for_execution`.

- [ ] **Step 3: Implement the preflight and context persistence**

For `checkout_build`, invoke ref resolution after `build_step1_preflight_interaction` has validated entry inputs but before `execute_step`. For resolved refs, preserve the user value in `<side>_requested_ref`, store exact ref/commit metadata, and pass `<side>_resolved_commit` to Step1 as the immutable checkout target. For ambiguity or no match, return a checkpoint interaction containing candidate refs and commits. For `artifact_inputs`, defer this work until final-artifact parsing proves that a concrete side needs Maven coordinate enrichment.

- [ ] **Step 4: Write failing source-only confirmation and unchanged-input loop tests**

```python
def test_source_only_step1_input_requires_revision_confirmation(self):
    context = {"base_source_project_dir": str(project_dir), "current_branch": "current"}
    updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)
    self.assertEqual(interaction["reason_code"], "step1_source_revision_confirmation_required")
    self.assertIn("base_branch", interaction["required_fields"])

def test_confirmed_source_revision_is_stored_as_immutable_commit(self):
    context = {"base_branch": base_commit, "current_branch": current_commit}
    updated, interaction = run_step.resolve_step1_refs_for_execution(context, project_dir)
    self.assertIsNone(interaction)
    self.assertEqual(updated["base_resolved_commit"], base_commit)

def test_repeating_same_unconfirmed_ref_does_not_execute_step1(self):
    interaction = run_step.build_step1_ref_confirmation_interaction(context, resolution)
    with self.assertRaisesRegex(run_step.StepError, "必须补充"):
        run_step.validate_pending_interaction_response(interaction, {"action": "continue"})
```

The source-only interaction must require the relevant `base_branch` or `current_branch` field, show the detected commit as a candidate, and keep `must_wait_for_user_reply=true`. A response that does not change the required field must fail validation before Maven execution.

- [ ] **Step 5: Run Step1 state tests and verify GREEN**

Run: `python3 -m unittest tests.test_run_step_main_state`

Expected: all Step1 checkpoint and state tests pass.

---

### Task 3: 修正坐标补全优先级并固定 worktree revision

**Files:**
- Modify: `scripts/s1_dep_diff.py`
- Modify: `tests/test_step1_packaged_deps.py`

**Interfaces:**
- Consumes: orchestrated Step1 fields `<side>_resolved_ref` and `<side>_resolved_commit`
- Changes: `_collect_runtime_deps_for_artifact_input(...)` must select confirmed ref before source directory
- Changes: `create_branch_worktree(ref, work_dir)` receives an exact resolved ref or commit

- [ ] **Step 1: Write a failing regression test for branch-over-source precedence**

```python
def test_artifact_coordinate_enrichment_prefers_confirmed_branch_over_source_directory(self):
    deps, meta = step1._collect_runtime_deps_for_artifact_input(
        source_project_dir=self.repo,
        branch="current-release",
        work_dir=self.repo,
        primary_module="app",
        side="current",
    )
    self.assertEqual(meta["source_mode"], "checkout_branch")
    self.assertEqual(meta["branch"], "current-release")
```

- [ ] **Step 2: Run the regression test and verify RED**

Run: `python3 -m unittest tests.test_step1_packaged_deps.Step1PackagedDepsTest.test_artifact_coordinate_enrichment_prefers_confirmed_branch_over_source_directory`

Expected: `source_mode` is currently `source_project_dir`.

- [ ] **Step 3: Implement branch-first enrichment and source-only guard**

```python
if branch:
    runtime_deps, meta = get_runtime_deps_by_switching_branch(
        branch,
        work_dir,
        primary_module=primary_module,
        modules=modules,
        jdk_field=jdk_field,
        jdk_home=jdk_home,
        side=side,
        artifact_path=artifact_path,
        observer=observer,
    )
    return runtime_deps, {"source_mode": "checkout_branch", **meta}
if source_dir:
    raise SourceRevisionConfirmationRequiredError(side, source_dir, artifact_path)
return {}, {"source_mode": "none", "source_project_dir": "", "list_command": ""}
```

Automatic-build orchestration converts a confirmed source ref into `branch=<commit>` before checkout. Direct-artifact execution resolves the ref lazily inside this function only when unresolved nested JAR coordinates trigger the loader. Standalone source-only execution must fail with a specific confirmation-required error instead of directly analyzing the mutable checkout.

- [ ] **Step 4: Add a real Git fixture test for one repository, two refs, one source path**

Create base/current commits with different dependency lists, provide the same repository path for both source directory fields, and assert each side invokes Maven in its own detached worktree at the expected commit.

- [ ] **Step 5: Run Step1 packaged dependency tests and verify GREEN**

Run: `python3 -m unittest tests.test_step1_packaged_deps`

Expected: all tests pass and the original workspace HEAD remains unchanged.

---

### Task 4: 补齐观测数据、文档与端到端回归

**Files:**
- Modify: `scripts/step1_observability.py`
- Modify: `scripts/s1_dep_diff.py`
- Modify: `scripts/smoke_regression.py`
- Modify: `README.md`
- Modify: `RUNBOOK.md`
- Modify: `docs/developer/architecture.md`
- Modify: `docs/user/outputs.md`
- Test: `tests/test_step1_observability.py`
- Test: `tests/test_user_visible_output_contract.py`

**Interfaces:**
- Adds nested `details` object to Step1 progress events without changing existing top-level fields
- Adds `ref_resolution` phase with requested/ref/commit/mode/candidate-count evidence

- [ ] **Step 1: Write failing observability tests**

```python
def test_ref_resolution_event_records_requested_and_resolved_revision(self):
    event = observer.event(
        "ref_resolution",
        "completed",
        "resolved",
        details={
            "requested_ref": "release-2.0.0",
            "resolved_ref": "origin/release-2.0.0",
            "resolved_commit": commit,
            "resolution_mode": "unique_remote",
            "candidate_count": 1,
        },
    )
    self.assertEqual(event["details"]["resolved_commit"], commit)
```

- [ ] **Step 2: Run observability tests and verify RED**

Run: `python3 -m unittest tests.test_step1_observability`

Expected: `Step1Observer.event` does not yet accept `details`.

- [ ] **Step 3: Implement structured ref-resolution events and update user/developer documentation**

Document that source directories may be identical, branch/commit defines side identity, remote matching uses only already-fetched remote-tracking refs, and ambiguous matches pause before Maven work.

- [ ] **Step 4: Extend orchestrator smoke with the formerly missing combined case**

The smoke fixture must provide both `current_source_project_dir` and a current branch pointing at a different commit, then assert the branch dependency coordinate wins and the progress log records `checkout_branch`/resolved commit.

- [ ] **Step 5: Run focused and broad verification**

Run:

```bash
python3 -m py_compile scripts/step1_ref_resolution.py scripts/run_step.py scripts/s1_dep_diff.py scripts/step1_observability.py
python3 -m unittest tests.test_step1_ref_resolution tests.test_step1_packaged_deps tests.test_step1_observability tests.test_run_step_main_state tests.test_user_visible_output_contract
python3 scripts/smoke_regression.py --group orchestrator
python3 scripts/smoke_regression.py --group core
```

Expected: compilation succeeds, all selected unit tests pass, and both smoke groups print `SMOKE PASS`.

- [ ] **Step 6: Review the staged snapshot and commit only this feature**

Create an index-only snapshot with `git checkout-index`, rerun the focused verification there, confirm unrelated dirty-worktree changes are absent, then commit with:

```bash
git commit -m "fix(step1): resolve source refs before coordinate enrichment"
```
