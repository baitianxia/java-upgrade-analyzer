# Upgrade Analyzer Interaction And Docs Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an end-to-end interaction and documentation experience where runtime checkpoints, `.upgrade-report/` files, and skill documentation guide users through objective analysis results without exposing internal protocol details as the main user experience.

**Architecture:** Add a dependency-level Step4 selection view as the user-facing bridge into Step5, while preserving API-level evidence as complete facts. Centralize checkpoint presentation helpers so every checkpoint can expose a user-facing decision card plus machine-readable recovery fields. Update Step6 and documentation to keep final reports objective and keep program/runtime files out of ordinary user reading paths.

**Tech Stack:** Python standard library, `unittest`, existing `run_step.py` orchestrator, existing Step4/Step5/Step6 scripts, Markdown documentation under `docs/`.

## Global Constraints

- Final reports must present objective analysis results, evidence, and limitations; they must not tell users what to modify, test, release, or prioritize.
- Step4-to-Step5 user selection must be dependency-package level, not API-row level.
- `evidence/api_changes/all_changed_apis.csv` remains the complete API fact set and must not be replaced by dependency summaries.
- `deliverables/` is for user-facing deliverables, `evidence/` is for review evidence, and `.runtime/` is for program and Agent state.
- User-visible checkpoint text must avoid leading with internal fields such as `action_requirements`, `selection_resolution`, `response_schema`, or `runtime_rules`.
- Accuracy and evidence completeness remain higher priority than shorter output.
- Runtime changes must keep existing resume semantics: user replies are still normalized into `intent_patch`, `selected_targets`, `step5_selected_coords`, or `step5_selected_names`.

---

## File Structure

Modify these files:

- `scripts/s4_contract.py`
  - Add constants for dependency-level Step4 files if no existing constants cover them.
- `scripts/s4_jar_compare.py`
  - Produce `changed_dependencies.csv` and `changed_dependencies.md` under `evidence/api_changes/`.
  - Reuse `all_changed_apis.csv` rows and per-dependency summaries; do not re-run expensive analysis.
- `scripts/run_step.py`
  - Use dependency-level Step4 summaries for checkpoint `selection_options`.
  - Add user-facing decision-card fields and improve console rendering.
  - Keep machine-readable fields for resume and Agent normalization.
- `scripts/s6_report.py`
  - Ensure final report wording stays objective and evidence-oriented.
  - Add or keep an appendix entry for `changed_dependencies.md/csv`.
- `docs/user/outputs.md`
  - Document dependency-level Step4 selection and the difference between `changed_dependencies.*` and `all_changed_apis.csv`.
- `README.md`
  - Add a short user path from running the skill to reading `deliverables/report.md` and Step4 dependency choices.
- `RUNBOOK.md`
  - Document operator recovery examples using dependency-level `selected_targets`.
- `SKILL.md`
  - Update Agent interaction rules: translate checkpoint JSON into a user-facing decision card.
- `tests/test_step4_stability.py`
  - Add tests for dependency-level Step4 files.
- `tests/test_run_step_main_state.py`
  - Add tests for Step4 checkpoint options and decision card output.
- `tests/test_step5_key_matching.py`
  - Add or update tests that dependency-level `selected_targets` still filter Step5 inputs correctly.
- `tests/test_step6_report.py` or existing Step6 report test file
  - Add tests that report text avoids prescriptive action wording and includes evidence links.

Create these files if they do not already exist:

- `tests/test_user_visible_output_contract.py`
  - Contract tests for user-visible wording, file layering, and forbidden internal/proscriptive phrases.

---

### Task 1: Generate Dependency-Level Step4 Selection Files

**Files:**
- Modify: `scripts/s4_contract.py`
- Modify: `scripts/s4_jar_compare.py`
- Test: `tests/test_step4_stability.py`

**Interfaces:**
- Consumes: `all_changed_apis.csv` rows with at least `coord`, `change_type`, `severity`, `symbol_kind`, and `api_name` / `api`.
- Produces:
  - `build_changed_dependency_rows(api_rows: list[dict]) -> list[dict]`
  - `write_changed_dependencies(api_rows: list[dict], output_dir: Path) -> tuple[Path, Path]`
  - Files:
    - `evidence/api_changes/changed_dependencies.csv`
    - `evidence/api_changes/changed_dependencies.md`

- [ ] **Step 1: Add failing tests for dependency-level aggregation**

Add this test to `tests/test_step4_stability.py`:

```python
def test_changed_dependencies_view_groups_api_rows_by_coord(self):
    from s4_jar_compare import build_changed_dependency_rows

    rows = [
        {
            "coord": "com.acme:alpha",
            "change_type": "removed",
            "severity": "P1",
            "api_name": "com.acme.Alpha.removed",
            "symbol_kind": "method",
        },
        {
            "coord": "com.acme:alpha",
            "change_type": "signature_changed",
            "severity": "P2",
            "api_name": "com.acme.Alpha.changed",
            "symbol_kind": "method",
        },
        {
            "coord": "com.acme:beta",
            "change_type": "behavior_changed",
            "severity": "P0",
            "api_name": "com.acme.Beta.risky",
            "symbol_kind": "field",
        },
    ]

    result = build_changed_dependency_rows(rows)

    self.assertEqual([item["coord"] for item in result], ["com.acme:alpha", "com.acme:beta"])
    self.assertEqual(result[0]["selection_key"], "coord:com.acme:alpha")
    self.assertEqual(result[0]["dependency_name"], "alpha")
    self.assertEqual(result[0]["changed_api_count"], 2)
    self.assertEqual(result[0]["high_risk_api_count"], 1)
    self.assertEqual(result[0]["change_types"], "removed, signature_changed")
    self.assertEqual(result[1]["high_risk_api_count"], 1)
```

Add this test to the same file:

```python
def test_write_changed_dependencies_outputs_csv_and_markdown(self):
    from s4_jar_compare import write_changed_dependencies

    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        rows = [
            {
                "coord": "com.acme:alpha",
                "change_type": "removed",
                "severity": "P1",
                "api_name": "com.acme.Alpha.removed",
                "symbol_kind": "method",
            }
        ]

        csv_path, md_path = write_changed_dependencies(rows, output_dir)

        self.assertTrue(csv_path.exists())
        self.assertTrue(md_path.exists())
        csv_text = csv_path.read_text(encoding="utf-8")
        md_text = md_path.read_text(encoding="utf-8")
        self.assertIn("selection_key,coord,dependency_name,changed_api_count", csv_text)
        self.assertIn("coord:com.acme:alpha", csv_text)
        self.assertIn("本文件回答：哪些依赖包发生 API 变化", md_text)
        self.assertIn("`coord:com.acme:alpha`", md_text)
        self.assertIn("完整 API 明细", md_text)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
python3 -m unittest tests.test_step4_stability.Step4StabilityTest.test_changed_dependencies_view_groups_api_rows_by_coord tests.test_step4_stability.Step4StabilityTest.test_write_changed_dependencies_outputs_csv_and_markdown
```

Expected: FAIL because `build_changed_dependency_rows` and `write_changed_dependencies` do not exist.

- [ ] **Step 3: Add constants**

In `scripts/s4_contract.py`, add:

```python
CHANGED_DEPENDENCIES_CSV = "changed_dependencies.csv"
CHANGED_DEPENDENCIES_MD = "changed_dependencies.md"
```

- [ ] **Step 4: Implement aggregation helpers**

In `scripts/s4_jar_compare.py`, near other output helpers, add:

```python
def _dependency_name_from_coord(coord):
    parts = [part.strip() for part in str(coord or "").split(":")]
    return parts[1] if len(parts) >= 2 else ""


def _is_high_risk_api_row(row):
    severity = str((row or {}).get("severity") or "").strip().upper()
    change_type = str((row or {}).get("change_type") or "").strip().lower()
    return severity in {"P0", "P1", "HIGH", "CRITICAL"} or change_type in {
        "removed",
        "signature_changed",
        "method_removed",
        "field_removed",
        "class_removed",
    }


def build_changed_dependency_rows(api_rows):
    grouped = {}
    for row in api_rows or []:
        coord = str((row or {}).get("coord") or "").strip()
        if not coord:
            continue
        item = grouped.setdefault(
            coord,
            {
                "selection_key": f"coord:{coord}",
                "coord": coord,
                "dependency_name": _dependency_name_from_coord(coord),
                "changed_api_count": 0,
                "high_risk_api_count": 0,
                "change_type_set": set(),
                "symbol_kind_set": set(),
            },
        )
        item["changed_api_count"] += 1
        if _is_high_risk_api_row(row):
            item["high_risk_api_count"] += 1
        change_type = str((row or {}).get("change_type") or "").strip()
        symbol_kind = str((row or {}).get("symbol_kind") or "").strip()
        if change_type:
            item["change_type_set"].add(change_type)
        if symbol_kind:
            item["symbol_kind_set"].add(symbol_kind)

    result = []
    for item in grouped.values():
        result.append(
            {
                "selection_key": item["selection_key"],
                "coord": item["coord"],
                "dependency_name": item["dependency_name"],
                "changed_api_count": item["changed_api_count"],
                "high_risk_api_count": item["high_risk_api_count"],
                "change_types": ", ".join(sorted(item["change_type_set"])),
                "symbol_kinds": ", ".join(sorted(item["symbol_kind_set"])),
                "detail": f"s4_per_dependency/{make_per_dependency_dirname(item['coord'])}/summary.json",
            }
        )
    return sorted(result, key=lambda row: (-int(row["high_risk_api_count"]), row["coord"]))
```

If `make_per_dependency_dirname` is not imported in `s4_jar_compare.py`, import it from `s4_contract`.

- [ ] **Step 5: Implement file writer**

In `scripts/s4_jar_compare.py`, add:

```python
def write_changed_dependencies(api_rows, output_dir):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    dependency_rows = build_changed_dependency_rows(api_rows)
    csv_path = output_path / "changed_dependencies.csv"
    md_path = output_path / "changed_dependencies.md"
    fieldnames = [
        "selection_key",
        "coord",
        "dependency_name",
        "changed_api_count",
        "high_risk_api_count",
        "change_types",
        "symbol_kinds",
        "detail",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(dependency_rows)

    lines = [
        "# 发生 API 变化的依赖包",
        "",
        "本文件回答：哪些依赖包发生 API 变化，以及是否可作为 Step5 调用链分析范围。",
        "",
        "完整 API 明细：`all_changed_apis.csv`。",
        "",
        "| 选择值 | 依赖包 | 变化 API 数 | 高风险 API 数 | 主要变化类型 | 明细 |",
        "|---|---|---:|---:|---|---|",
    ]
    if dependency_rows:
        for row in dependency_rows:
            lines.append(
                f"| `{row['selection_key']}` | `{row['coord']}` | "
                f"{row['changed_api_count']} | {row['high_risk_api_count']} | "
                f"{row['change_types'] or '-'} | `{row['detail']}` |"
            )
    else:
        lines.append("| - | - | 0 | 0 | - | - |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return csv_path, md_path
```

- [ ] **Step 6: Call writer after `all_changed_apis.csv` is finalized**

In `scripts/s4_jar_compare.py`, find the block that writes `all_changed_apis.csv`. Immediately after that file is written and the final API rows are available, add:

```python
write_changed_dependencies(all_changed_rows, output_dir)
```

Use the actual local variable name that contains the final rows written to `all_changed_apis.csv`. If rows are only available by path, read them with the existing CSV reader helper and pass the parsed rows.

- [ ] **Step 7: Run tests**

Run:

```bash
python3 -m unittest tests.test_step4_stability.Step4StabilityTest.test_changed_dependencies_view_groups_api_rows_by_coord tests.test_step4_stability.Step4StabilityTest.test_write_changed_dependencies_outputs_csv_and_markdown
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add scripts/s4_contract.py scripts/s4_jar_compare.py tests/test_step4_stability.py
git commit -m "Add dependency-level Step4 selection view"
```

---

### Task 2: Use Dependency-Level Options In Step4 Checkpoint

**Files:**
- Modify: `scripts/run_step.py`
- Test: `tests/test_run_step_main_state.py`

**Interfaces:**
- Consumes:
  - `evidence/api_changes/changed_dependencies.csv`
  - fallback: `evidence/api_changes/all_changed_apis.csv`
- Produces:
  - `build_step5_dependency_selection_summary(report_dir: Path) -> dict`
  - Step4 `interaction.selection_options[]` with dependency-package entries.
  - Step4 `checklist_lines[]` with a user-facing decision card.

- [ ] **Step 1: Add failing test for Step4 dependency selection options**

Add this test to `tests/test_run_step_main_state.py`:

```python
def test_step4_checkpoint_uses_changed_dependencies_for_selection_options(self):
    with tempfile.TemporaryDirectory() as tmp:
        project_dir = Path(tmp) / "project"
        report_dir = project_dir / ".upgrade-report"
        api_dir = report_dir / "evidence" / "api_changes"
        api_dir.mkdir(parents=True, exist_ok=True)
        (api_dir / "changed_dependencies.csv").write_text(
            "selection_key,coord,dependency_name,changed_api_count,high_risk_api_count,change_types,symbol_kinds,detail\n"
            "coord:com.acme:alpha,com.acme:alpha,alpha,42,5,removed,method,s4_per_dependency/com.acme__alpha/summary.json\n",
            encoding="utf-8",
        )

        selection_resolution = run_step.build_report_dir_step5_selection_resolution(report_dir)

        self.assertTrue(selection_resolution["enabled"])
        self.assertEqual(selection_resolution["options"][0]["selection_key"], "coord:com.acme:alpha")
        self.assertEqual(selection_resolution["options"][0]["coord"], "com.acme:alpha")
        self.assertEqual(selection_resolution["options"][0]["api_count"], 42)
        self.assertEqual(selection_resolution["options"][0]["high_risk_api_count"], 5)
```

If this test class does not import `run_step`, use the same import style already present in the file.

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
python3 -m unittest tests.test_run_step_main_state.RunStepMainStateTest.test_step4_checkpoint_uses_changed_dependencies_for_selection_options
```

Expected: FAIL because `high_risk_api_count` is not populated and selection reads API rows only.

- [ ] **Step 3: Add reader helper**

In `scripts/run_step.py`, near `build_report_dir_step5_selection_resolution`, add:

```python
def step4_changed_dependencies_path(report_dir):
    return step4_api_changes_dir(report_dir) / "changed_dependencies.csv"


def build_step5_dependency_selection_summary(report_dir):
    dependency_rows = read_csv_rows(step4_changed_dependencies_path(report_dir))
    if dependency_rows:
        available_targets = []
        for row in dependency_rows:
            coord = str(row.get("coord") or "").strip()
            if not coord:
                continue
            available_targets.append(
                {
                    "selection_key": str(row.get("selection_key") or f"coord:{coord}").strip(),
                    "coord": coord,
                    "name": str(row.get("dependency_name") or _artifact_name_from_coord(coord)).strip(),
                    "api_count": int(row.get("changed_api_count") or 0),
                    "high_risk_api_count": int(row.get("high_risk_api_count") or 0),
                    "change_types": str(row.get("change_types") or "").strip(),
                    "detail": str(row.get("detail") or "").strip(),
                }
            )
        return {
            "available_targets": available_targets,
            "available_target_count": len(available_targets),
            "source_file": str(step4_changed_dependencies_path(report_dir)),
        }
    all_rows = read_csv_rows(step4_api_changes_dir(report_dir) / "all_changed_apis.csv")
    fallback = build_step5_selection_summary(all_rows)
    fallback["source_file"] = str(step4_api_changes_dir(report_dir) / "all_changed_apis.csv")
    return fallback
```

- [ ] **Step 4: Extend option normalization**

In `build_interaction_selection_options`, preserve optional fields:

```python
"high_risk_api_count": (item or {}).get("high_risk_api_count"),
"change_types": str((item or {}).get("change_types") or "").strip(),
"detail": str((item or {}).get("detail") or "").strip(),
```

- [ ] **Step 5: Update `build_report_dir_step5_selection_resolution`**

Replace its direct `all_changed_apis.csv` aggregation with:

```python
target_summary = build_step5_dependency_selection_summary(report_dir)
selection_options = build_interaction_selection_options(
    [
        {
            "selection_key": item.get("selection_key") or f"coord:{item.get('coord')}",
            "coord": item.get("coord"),
            "name": item.get("name"),
            "api_count": item.get("api_count"),
            "high_risk_api_count": item.get("high_risk_api_count"),
            "change_types": item.get("change_types"),
            "detail": item.get("detail"),
            "label": item.get("coord") or item.get("name"),
        }
        for item in target_summary.get("available_targets", [])
    ]
)
```

- [ ] **Step 6: Update Step4 checkpoint checklist lines**

In the `if step_id == "step4":` checkpoint block, replace the existing "Step5 可选调用链分析范围" lines with:

```python
checklist_lines.append("当前需要确认：Step5 是全量分析，还是只分析部分依赖包？")
checklist_lines.append("推荐默认动作：如果依赖包数量不多，选择 continue 全量进入 Step5。")
checklist_lines.append("如果依赖包很多，请从候选依赖包中选择一个或多个 selection_key。")
checklist_lines.append("候选依赖包来自 evidence/api_changes/changed_dependencies.csv。")
```

When rendering each option, include high-risk count:

```python
f"  - {item.get('selection_key')} | {item.get('coord')} | "
f"changed_api_count={item.get('api_count')} | high_risk_api_count={item.get('high_risk_api_count') or 0}"
```

- [ ] **Step 7: Run focused tests**

Run:

```bash
python3 -m unittest tests.test_run_step_main_state.RunStepMainStateTest.test_step4_checkpoint_uses_changed_dependencies_for_selection_options
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add scripts/run_step.py tests/test_run_step_main_state.py
git commit -m "Use dependency-level choices in Step4 checkpoint"
```

---

### Task 3: Add User-Facing Decision Card Rendering

**Files:**
- Modify: `scripts/run_step.py`
- Test: `tests/test_run_step_main_state.py`

**Interfaces:**
- Consumes: `interaction` payloads.
- Produces:
  - `build_user_decision_card(interaction: dict) -> list[str]`
  - Console output that leads with user-facing question, recommended action, choices, candidates, and reply examples.

- [ ] **Step 1: Add failing test for decision card text**

Add this test to `tests/test_run_step_main_state.py`:

```python
def test_user_decision_card_hides_internal_fields_and_shows_direct_replies(self):
    interaction = {
        "step_id": "step4",
        "question": "Step5 是全量分析，还是只分析部分依赖包？",
        "recommended_action": "依赖包数量不多时，选择全量继续。",
        "options": [
            {"id": "continue", "label": "全量继续"},
            {"id": "rerun_current_step", "label": "补材料后重跑"},
        ],
        "selection_options": [
            {
                "selection_key": "coord:com.acme:alpha",
                "coord": "com.acme:alpha",
                "api_count": 42,
                "high_risk_api_count": 5,
            }
        ],
        "selection_resolution": {"enabled": True},
        "action_requirements": {"continue": {"required_fields": []}},
        "files_to_review": ["/tmp/.upgrade-report/evidence/api_changes/changed_dependencies.md"],
    }

    lines = run_step.build_user_decision_card(interaction)
    text = "\n".join(lines)

    self.assertIn("当前需要确认：Step5 是全量分析，还是只分析部分依赖包？", text)
    self.assertIn("推荐动作：依赖包数量不多时，选择全量继续。", text)
    self.assertIn("`coord:com.acme:alpha`", text)
    self.assertIn("你可以直接回复：", text)
    self.assertNotIn("action_requirements", text)
    self.assertNotIn("selection_resolution", text)
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
python3 -m unittest tests.test_run_step_main_state.RunStepMainStateTest.test_user_decision_card_hides_internal_fields_and_shows_direct_replies
```

Expected: FAIL because `build_user_decision_card` does not exist.

- [ ] **Step 3: Implement decision card helper**

In `scripts/run_step.py`, near `emit_interaction_required`, add:

```python
def build_user_decision_card(interaction):
    lines = []
    question = str((interaction or {}).get("question") or "请确认当前结果，然后继续。").strip()
    lines.append(f"当前需要确认：{question}")

    reason = str((interaction or {}).get("user_reason") or (interaction or {}).get("reason") or "").strip()
    if reason:
        lines.append(f"为什么停下：{reason}")

    recommended = str((interaction or {}).get("recommended_action") or "").strip()
    if recommended:
        lines.append(f"推荐动作：{recommended}")

    options = list((interaction or {}).get("options") or [])
    if options:
        lines.append("可选动作：")
        for option in options:
            label = option.get("label") or option.get("id")
            desc = option.get("description") or ""
            suffix = f" - {desc}" if desc else ""
            lines.append(f"- `{option.get('id')}`：{label}{suffix}")

    selection_options = list((interaction or {}).get("selection_options") or [])
    if selection_options:
        lines.append("候选依赖包：")
        lines.append("| 选择值 | 依赖包 | 变化 API 数 | 高风险 API 数 |")
        lines.append("|---|---|---:|---:|")
        for item in selection_options[:10]:
            lines.append(
                f"| `{item.get('selection_key')}` | `{item.get('coord') or ''}` | "
                f"{item.get('api_count') or 0} | {item.get('high_risk_api_count') or 0} |"
            )

    files_to_review = list((interaction or {}).get("files_to_review") or [])
    if files_to_review:
        lines.append("完整候选或证据文件：")
        for path in files_to_review[:5]:
            lines.append(f"- `{path}`")

    if selection_options:
        first_key = selection_options[0].get("selection_key") or "<selection_key>"
        lines.append("你可以直接回复：")
        lines.append("- “全量继续”")
        lines.append(f"- “只分析 {first_key}”")
        lines.append("- “我补充依赖源码目录 /path/to/repo 后重跑”")
    elif options:
        lines.append("你可以直接回复选项名称，例如：“继续”或“补材料后重跑”。")
    return lines
```

- [ ] **Step 4: Use decision card in console rendering**

In `emit_interaction_required`, before printing raw checklist lines, add:

```python
for line in build_user_decision_card(interaction):
    sys.stderr.write(f"{line}\n")
```

Keep existing JSON output unchanged.

- [ ] **Step 5: Run focused test**

Run:

```bash
python3 -m unittest tests.test_run_step_main_state.RunStepMainStateTest.test_user_decision_card_hides_internal_fields_and_shows_direct_replies
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/run_step.py tests/test_run_step_main_state.py
git commit -m "Render user-facing checkpoint decision cards"
```

---

### Task 4: Keep Step6 Report Objective

**Files:**
- Modify: `scripts/s6_report.py`
- Test: `tests/test_step5_key_matching.py` or create `tests/test_step6_report.py`

**Interfaces:**
- Consumes: existing Step6 inputs.
- Produces:
  - `deliverables/report.md` text that avoids prescriptive action phrases.
  - Appendix entries for `evidence/api_changes/changed_dependencies.md` and `.csv`.

- [ ] **Step 1: Add forbidden wording test**

Create `tests/test_step6_report.py` if it does not exist:

```python
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR / "scripts"))

import s6_report  # noqa: E402


class Step6ReportObjectivityTest(unittest.TestCase):
    def test_report_template_does_not_use_prescriptive_action_words(self):
        forbidden = [
            "建议修改",
            "建议验证",
            "应该修改",
            "应该验证",
            "发布建议",
            "处置建议",
        ]
        text = "\n".join(s6_report.build_report_sections_for_test_only())
        for phrase in forbidden:
            self.assertNotIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
```

If `build_report_sections_for_test_only()` does not exist, Task 4 Step 2 will add it as a narrow test seam returning static headings and fixed explanatory paragraphs, not real project data.

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
python3 -m unittest tests.test_step6_report
```

Expected: FAIL because `build_report_sections_for_test_only` does not exist.

- [ ] **Step 3: Add test seam and appendix entries**

In `scripts/s6_report.py`, add:

```python
def build_report_sections_for_test_only():
    return [
        "核心结论",
        "结论限制",
        "分析结果总表",
        "附录",
        "本报告只呈现分析结果、证据和结论限制，不替使用者决定修改、验证或发布动作。",
    ]
```

Update appendix file list to include:

```markdown
| `evidence/api_changes/changed_dependencies.md` | 依赖包维度的 Step4 变化摘要；用于选择 Step5 分析范围 |
| `evidence/api_changes/changed_dependencies.csv` | 依赖包维度的结构化清单；供筛选和自动化使用 |
```

- [ ] **Step 4: Remove prescriptive wording from report body**

Search in `scripts/s6_report.py`:

```bash
rg -n "建议|应该|修复|验证|发布|处置" scripts/s6_report.py
```

For user-facing report strings, replace prescriptive wording with objective evidence wording:

```text
证据入口：
结论限制：
未完成分析原因：
```

Keep internal variable names unchanged if they are not emitted into the report.

- [ ] **Step 5: Run tests**

Run:

```bash
python3 -m unittest tests.test_step6_report tests.test_step5_key_matching.Step5KeyMatchingTest.test_step6_report_lists_runtime_findings_as_program_file
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/s6_report.py tests/test_step6_report.py tests/test_step5_key_matching.py
git commit -m "Keep Step6 report objective"
```

---

### Task 5: Update User And Agent Documentation

**Files:**
- Modify: `README.md`
- Modify: `RUNBOOK.md`
- Modify: `SKILL.md`
- Modify: `docs/user/outputs.md`
- Test: `tests/test_user_visible_output_contract.py`

**Interfaces:**
- Consumes: design in `docs/superpowers/specs/2026-07-10-upgrade-analyzer-interaction-docs-design.md`.
- Produces:
  - User docs explaining dependency-level Step4 choices.
  - Agent docs requiring decision-card translation.
  - Contract tests for documentation text.

- [ ] **Step 1: Add documentation contract tests**

Create `tests/test_user_visible_output_contract.py`:

```python
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


class UserVisibleOutputContractTest(unittest.TestCase):
    def read(self, relative):
        return (ROOT_DIR / relative).read_text(encoding="utf-8")

    def test_outputs_doc_explains_three_report_layers(self):
        text = self.read("docs/user/outputs.md")
        self.assertIn("deliverables/", text)
        self.assertIn("evidence/", text)
        self.assertIn(".runtime/", text)
        self.assertIn("交付", text)
        self.assertIn("复核", text)
        self.assertIn("程序", text)

    def test_outputs_doc_explains_dependency_level_step4_selection(self):
        text = self.read("docs/user/outputs.md")
        self.assertIn("changed_dependencies.md", text)
        self.assertIn("changed_dependencies.csv", text)
        self.assertIn("依赖包维度", text)
        self.assertIn("all_changed_apis.csv", text)
        self.assertIn("完整 API", text)

    def test_skill_doc_requires_user_facing_decision_card(self):
        text = self.read("SKILL.md")
        self.assertIn("决策卡片", text)
        self.assertIn("可直接回复", text)
        self.assertIn("不要把 action_requirements", text)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
python3 -m unittest tests.test_user_visible_output_contract
```

Expected: FAIL until docs are updated.

- [ ] **Step 3: Update `docs/user/outputs.md`**

In the Step4 section, add:

```markdown
### 依赖包维度选择入口

Step4 完成后，如果要决定 Step5 是全量分析还是只分析部分依赖包，优先看：

| 文件 | 用途 |
|---|---|
| `evidence/api_changes/changed_dependencies.md` | 给人看的依赖包维度清单 |
| `evidence/api_changes/changed_dependencies.csv` | 结构化依赖包清单 |
| `evidence/api_changes/all_changed_apis.csv` | 完整 API 变化事实集合 |

普通选择应使用 `changed_dependencies.md` 中的 `selection_key`，例如 `coord:com.foo:bar`。
`all_changed_apis.csv` 可能很大，它用于核对 API 明细，不作为普通选择入口。
```

- [ ] **Step 4: Update `SKILL.md`**

Add an Agent rule near checkpoint handling:

```markdown
- checkpoint 转述必须先形成用户可读的“决策卡片”：当前需要确认什么、为什么停下、推荐默认动作、可选动作、候选对象、完整候选文件、用户可以直接怎么回复。
- Agent 不要把 `action_requirements`、`selection_resolution`、`response_schema`、`runtime_rules` 作为普通用户的主信息；这些字段只用于构造恢复命令。
- Step4 后进入 Step5 的候选对象必须按依赖包维度展示，优先引用 `evidence/api_changes/changed_dependencies.md`，不要要求用户从 `all_changed_apis.csv` 中逐行挑 API。
```

- [ ] **Step 5: Update `README.md`**

Add a short result-reading path:

```markdown
## 如何阅读结果

1. 先看 `.upgrade-report/deliverables/report.md`，了解客观分析结果和结论限制。
2. 如果需要核对依赖 API 变化，先看 `.upgrade-report/evidence/api_changes/changed_dependencies.md`。
3. 如果需要核对完整 API 明细，再看 `.upgrade-report/evidence/api_changes/all_changed_apis.csv`。
4. 如果需要核对调用链证据，看 `.upgrade-report/evidence/call_chain/alerts.csv`。
5. `.upgrade-report/.runtime/` 是程序状态目录，普通阅读不需要进入。
```

- [ ] **Step 6: Update `RUNBOOK.md`**

Add recovery examples:

```markdown
Step4 后只分析部分依赖包：

```bash
python3 "$SKILL/scripts/run_step.py" --step auto \
  --project-dir . \
  --report-dir .upgrade-report \
  --response-json '{"intent_patch":{"action":"continue","set":{"selected_targets":["coord:com.foo:bar"]}}}'
```
```

- [ ] **Step 7: Run documentation tests**

Run:

```bash
python3 -m unittest tests.test_user_visible_output_contract
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add README.md RUNBOOK.md SKILL.md docs/user/outputs.md tests/test_user_visible_output_contract.py
git commit -m "Document user-facing interaction model"
```

---

### Task 6: End-To-End Regression And Old-Path Scan

**Files:**
- Modify only if tests reveal gaps.

**Interfaces:**
- Consumes all previous tasks.
- Produces verified behavior across Step4, Step5 selection, Step6 report, and docs contracts.

- [ ] **Step 1: Run focused unit tests**

Run:

```bash
python3 -m unittest \
  tests.test_step4_stability \
  tests.test_run_step_main_state \
  tests.test_step5_key_matching \
  tests.test_step6_report \
  tests.test_user_visible_output_contract
```

Expected: PASS.

- [ ] **Step 2: Run syntax compilation**

Run:

```bash
python3 -m py_compile \
  scripts/s4_contract.py \
  scripts/s4_jar_compare.py \
  scripts/run_step.py \
  scripts/s6_report.py \
  tests/test_step4_stability.py \
  tests/test_run_step_main_state.py \
  tests/test_step5_key_matching.py \
  tests/test_step6_report.py \
  tests/test_user_visible_output_contract.py
```

Expected: no output and exit code 0.

- [ ] **Step 3: Run old-path and forbidden-copy scans**

Run:

```bash
rg -n "s5_call_chain/|s4_jar_compare/|\\.upgrade-report/s5_|\\.upgrade-report/s4_" scripts docs README.md RUNBOOK.md SKILL.md tests -g '!docs/archive/**'
```

Expected: no matches except script names such as `s5_call_chain.py` or archived historical docs.

Run:

```bash
rg -n "建议修改|建议验证|应该修改|应该验证|发布建议|处置建议" scripts/s6_report.py docs/user README.md
```

Expected: no matches in user-visible final report generation paths. Matches in design docs or tests that assert forbidden phrases are acceptable.

- [ ] **Step 4: Run real project regression matrix if Step4/Step5 behavior changed materially**

Run:

```bash
python3 scripts/real_project_regression.py \
  --case all \
  --report-root /private/tmp/jua-real-regression-interaction-docs \
  --json-out /private/tmp/jua-real-regression-interaction-docs/result.json
```

Expected: all cases passed.

Then run:

```bash
python3 scripts/quality_signal_audit.py /private/tmp/jua-real-regression-interaction-docs/result.json
```

Expected: `status` is `clean`.

- [ ] **Step 5: Inspect generated output structure**

Run:

```bash
find /private/tmp/jua-real-regression-interaction-docs -maxdepth 4 -type f | sort | sed -n '1,160p'
```

Expected: each case includes:

```text
evidence/api_changes/all_changed_apis.csv
evidence/api_changes/changed_dependencies.csv
evidence/api_changes/changed_dependencies.md
evidence/call_chain/alerts.csv
evidence/call_chain/summary.json
.runtime/indexes/s5_query_index.json
```

- [ ] **Step 6: Final commit**

If any fixes were required during this task:

```bash
git add scripts tests docs README.md RUNBOOK.md SKILL.md
git commit -m "Verify interaction and docs overhaul"
```

If no fixes were required, do not create an empty commit.

---

## Self-Review Notes

Spec coverage:

- Runtime checkpoint design is covered by Tasks 2 and 3.
- Dependency-package Step4 selection is covered by Tasks 1 and 2.
- `.upgrade-report/` and docs layering are covered by Task 5.
- Objective Step6 reporting is covered by Task 4.
- Verification and real-project regression are covered by Task 6.

Placeholder scan:

- No `TODO`, `TBD`, or unspecified implementation placeholders remain.
- Each code task includes concrete tests, implementation snippets, commands, and expected outcomes.

Type consistency:

- Dependency selection uses `selection_key`, `coord`, `dependency_name`, `changed_api_count`, `high_risk_api_count`, `change_types`, `symbol_kinds`, and `detail`.
- Runtime selection continues to use `selected_targets`, `step5_selected_coords`, and `step5_selected_names`.
