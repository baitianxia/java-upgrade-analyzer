# Step6 Evidence Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve the existing five-column Step6 API table while making every evidence-bearing summary link to the correct same-report call-chain explanation and exact `alerts.csv` filter.

**Architecture:** Extend the existing exact API-identity aggregation in `s6_report.py` to carry a unique `api_id`, then use one anchor helper for both the table link and explicit evidence anchor. Keep representative paths in the report and the complete path ledger in the existing `alerts.csv`; never infer an ID from a simple class or method name.

**Tech Stack:** Python 3 standard library, Markdown generation, `unittest` regression suite.

## Global Constraints

- Keep the columns exactly: `依赖坐标 | 变更 API | 变化 | 结论 | 证据摘要 / 未确认原因`.
- Do not change Step5 conclusions, path statuses, or `alerts.csv` fields.
- Do not add a user-facing output file.
- Use exact five-part API identity and a unique `api_id`; do not use simple-name fallback.
- Use explicit HTML anchors so Markdown-renderer anchor rules cannot break navigation.
- Keep the current report path display limit and always state displayed count, total count, and exact CSV filters when evidence is truncated.

---

### Task 1: Lock Evidence Identity and Navigation Behavior with Tests

**Files:**
- Modify: `tests/test_step5_key_matching.py`
- Test: `tests/test_step5_key_matching.py`

**Interfaces:**
- Consumes: `s6_report.build_impact_overview(alert_rows)` and `s6_report.render_api_result_table(findings)`.
- Produces: regression expectations for unique `api_id`, explicit anchor links, readable evidence navigation, and no link for ambiguous/missing IDs.

- [ ] **Step 1: Extend the confirmed/uncertain mixed-path test with stable IDs**

Add `api_id: API-exact-target` to both exact-identity alert rows and assert:

```python
self.assertIn(
    "[已确认链路 1 条；另有 1 条依赖引用尚未回溯到业务入口。查看具体链路](#api-api-exact-target)",
    report_text,
)
self.assertIn('<a id="api-api-exact-target"></a>', report_text)
self.assertIn("筛选 `api_id = API-exact-target`", report_text)
self.assertIn("`path_status = reachable` 是已确认链路", report_text)
self.assertIn("`path_status = uncertain` 是尚未回溯到业务入口的依赖引用", report_text)
```

- [ ] **Step 2: Add an uncertain-only navigation test**

Create one exact API with two `uncertain` alert rows and assert that the five-column table is unchanged, its summary says two dependency references are not traced to a business entry, and its link targets the same explicit `api_id` anchor.

- [ ] **Step 3: Add ambiguous and absent ID safety tests**

Create exact-identity alert rows with conflicting `api_id` values, then assert the readable summary remains but neither `#api-...` link nor evidence card is generated. Repeat with no `api_id`. This proves that Step6 does not guess from the API simple name.

- [ ] **Step 4: Add same-simple-name isolation coverage**

Create `a:b/com.alpha.StringUtils.isEmpty(String)` and `c:d/com.beta.StringUtils.isEmpty(String)` with different IDs and paths. Assert each table link, anchor, target signature, and path remains associated with its own exact identity.

- [ ] **Step 5: Run the focused tests and verify RED**

Run:

```bash
python3 -m unittest \
  tests.test_step5_key_matching.Step5KeyMatchingTest.test_s6_report_does_not_mix_uncertain_paths_into_confirmed_api_evidence \
  tests.test_step5_key_matching.Step5KeyMatchingTest.test_s6_report_links_uncertain_evidence_by_exact_api_id \
  tests.test_step5_key_matching.Step5KeyMatchingTest.test_s6_report_does_not_link_ambiguous_or_missing_api_id \
  tests.test_step5_key_matching.Step5KeyMatchingTest.test_s6_report_keeps_same_simple_names_in_separate_evidence_anchors -v
```

Expected: existing test fails on missing navigation text; new tests fail because `api_id` is not carried into report rows.

### Task 2: Carry Exact API IDs and Render Same-Report Evidence Navigation

**Files:**
- Modify: `scripts/s6_report.py:760-900`
- Modify: `scripts/s6_report.py:1600-1900`
- Test: `tests/test_step5_key_matching.py`

**Interfaces:**
- Consumes: alerts rows containing `api_id`, `path_status`, `path_occurrence_count`, and exact API identity fields.
- Produces: `_evidence_anchor(api_id) -> str`, result rows with `api_id`, linked summary text, and explicit evidence sections.

- [ ] **Step 1: Retain only a unique API ID in exact-identity aggregation**

Add `api_ids: set()` to each `build_impact_overview` accumulator, collect non-empty `row['api_id']`, and export:

```python
"api_id": next(iter(item["api_ids"])) if len(item["api_ids"]) == 1 else "",
```

This deliberately produces no ID when the same exact identity has conflicting IDs.

- [ ] **Step 2: Add one shared explicit-anchor helper**

Add:

```python
def _evidence_anchor(api_id):
    normalized = re.sub(r"[^a-z0-9_-]+", "-", str(api_id or "").strip().lower()).strip("-")
    return f"api-{normalized}" if normalized else ""
```

Use this helper for both table links and `<a id="..."></a>` output.

- [ ] **Step 3: Carry the unique ID into API result rows**

In `build_api_result_rows`, read `overview['api_id']` after exact five-part identity lookup and add:

```python
"api_id": str(overview.get("api_id") or "").strip(),
```

Do not fall back to API names or signatures outside that exact lookup.

- [ ] **Step 4: Make evidence summaries readable and clickable**

Change `_evidence_summary_text` so evidence-bearing rows with a valid anchor return Markdown links. Confirmed rows end with `查看具体链路`; uncertain rows end with `查看引用详情`. Rows without a valid anchor retain the same readable plain-text summary.

- [ ] **Step 5: Render explicit evidence anchors and exact ledger filters**

Update `_render_path_sample_cards` so each evidence-bearing row with a valid ID begins with:

```python
f'<a id="{anchor}"></a>'
```

The card must name the full API and ID, list the current paths, state `当前展示 X 条，共 Y 条` whenever truncated, and include:

```markdown
完整证据：打开 `evidence/call_chain/alerts.csv`，筛选 `api_id = ...`。
`path_status = reachable` 是已确认链路；`path_status = uncertain` 是尚未回溯到业务入口的依赖引用。
```

Only mention a status filter when that status has a non-zero count.

- [ ] **Step 6: Rename sample wording without expanding report size**

Change the section title from `调用链样例` to `调用链证据`, and replace vague `样例` wording with exact displayed and total counts. Keep `_paths_for_report(... )[:5]` unchanged.

- [ ] **Step 7: Run focused tests and verify GREEN**

Run the four Task 1 tests again. Expected: all pass.

### Task 3: Align User Documentation and Verify Existing Report Contracts

**Files:**
- Modify: `docs/user/outputs.md`
- Modify: `tests/test_step5_key_matching.py`
- Test: `tests/test_step5_key_matching.py`

**Interfaces:**
- Consumes: the final five-column table and same-report evidence section.
- Produces: accurate user guidance that starts from the table link and uses `alerts.csv` only for full-ledger review.

- [ ] **Step 1: Add a documentation regression assertion if an existing docs test is available**

Search the test suite for `docs/user/outputs.md`. If covered, extend that test to assert the document names the five columns, the clickable evidence summary, `api_id`, and `path_status`. If no docs test exists, keep the documentation change reviewed by `git diff --check` rather than creating a brittle whole-document snapshot.

- [ ] **Step 2: Update the output reading instructions**

Document this reading path:

```markdown
1. 在 Step6 五列表格中查看变化和结论。
2. 点击“证据摘要 / 未确认原因”中的链接，查看同报告内的具体链路。
3. 需要复核全部路径时，按报告给出的 `api_id` 和 `path_status` 筛选 `alerts.csv`。
```

State explicitly that no link is shown for a static not-found result because no call-chain evidence exists.

- [ ] **Step 3: Run all Step6-focused tests**

Run:

```bash
python3 -m unittest tests.test_step5_key_matching -k s6_report -v
```

Expected: all selected Step6 report tests pass and retain the exact five-column header.

- [ ] **Step 4: Run formatting checks**

Run:

```bash
python3 -m py_compile scripts/s6_report.py
git diff --check -- scripts/s6_report.py tests/test_step5_key_matching.py docs/user/outputs.md
```

Expected: both commands exit 0 with no output from `git diff --check`.

### Task 4: Full Regression and Real Dubbo Report Verification

**Files:**
- Verify: `scripts/s6_report.py`
- Verify: `tests/test_step5_key_matching.py`
- Verify: existing Dubbo report directory under `/private/tmp`

**Interfaces:**
- Consumes: completed implementation and the existing full Dubbo Step5 artifacts.
- Produces: fresh automated and real-output evidence that navigation is correct without changing analysis conclusions.

- [ ] **Step 1: Run the complete automated suite**

Run:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Expected: the complete suite passes with zero failures and zero errors.

- [ ] **Step 2: Regenerate Step6 from the existing real Dubbo artifacts**

Use the current `scripts/run_step.py` Step6 invocation against `/private/tmp/jua-dubbo-superpowers-fatjar-20260710` without rerunning or mutating Step5 evidence. Expected: `deliverables/report.md` is regenerated successfully.

- [ ] **Step 3: Audit real-report links and conclusions**

Check that:

- the report retains the five-column header;
- every `#api-...` table link has exactly one matching explicit `<a id="api-..."></a>`;
- every linked ID exists in `alerts.csv` under the same exact API identity;
- confirmed, uncertain, not-analyzed, and not-found API totals match the pre-change findings;
- no not-found row receives a call-chain link;
- at least one confirmed Dubbo API link leads to a concrete business path;
- at least one uncertain Dubbo API link leads to a concrete dependency reference and exact CSV filter.

Expected: zero broken links, zero cross-API identities, and unchanged conclusion counts.

- [ ] **Step 4: Review final diff for scope**

Run:

```bash
git diff --stat
git diff -- scripts/s6_report.py tests/test_step5_key_matching.py docs/user/outputs.md
```

Expected: changes are limited to Step6 evidence navigation, its tests, and aligned user documentation; unrelated pre-existing working-tree changes remain untouched.
