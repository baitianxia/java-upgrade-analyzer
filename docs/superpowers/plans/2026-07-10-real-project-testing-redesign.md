# Real Project Testing Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a release-quality test gate that surfaces false negatives, false positives, capability gaps, evidence weaknesses, and skipped real-project coverage before users receive the skill.

**Architecture:** Keep the current runners, but make their outputs stricter and more structured. `real_project_regression.py` produces per-case quality signals, `quality_signal_audit.py` normalizes and gates those signals, and `quality_gate.py` runs the audit as part of release/Step5 profiles. Repository tests validate this behavior with synthetic payloads and mocked real-project runs.

**Tech Stack:** Python 3 standard library, `unittest`, existing CSV/JSON report files, existing scripts under `scripts/`, existing tests under `tests/`.

## Global Constraints

- Normal CI must not require live network access.
- Existing real-project checkouts may be used when available, but missing checkouts are `infra_skip`, not success.
- P0/P1 correctness failures block release.
- P0/P1 capability gaps block release when the analyzer has available source, bytecode, dependency, or build evidence to do better.
- Evidence weaknesses block release when a human cannot reproduce the conclusion from output files.
- Every blocking real-project signal must be tied to implemented, planned, or waived fixture debt.
- Do not replace semantic tests with golden output snapshots only.
- Do not accept broad grep baselines as proof when owner or signature precision matters.

---

### Task 1: Canonical Quality Signal Model

**Files:**
- Modify: `scripts/quality_signal_audit.py`
- Modify: `tests/test_quality_signal_audit.py`

**Interfaces:**
- Produces: `QualitySignal(signal_type: str, severity: str, blocking: bool, case: str, step: str = "", symbol: str = "", message: str = "", count: int = 0, expected: str = "", actual: str = "", evidence: tuple[str, ...] = (), fixture_status: str = "", notes: str = "")`
- Produces: `normalize_signal(raw: dict) -> QualitySignal`
- Produces: `audit_real_project_payload(payload: dict) -> list[QualitySignal]`
- Produces: `summarize_signals(signals: list[QualitySignal]) -> dict`
- Consumes: Existing real-project payload fields: `results`, `case`, `status`, `summary`, `checks`, `quality_signals`.

- [ ] **Step 1: Write failing tests for the canonical model**

Add tests to `tests/test_quality_signal_audit.py`:

```python
def test_normalize_quality_signal_defaults_blocking_from_type_and_severity(self):
    signal = quality_signal_audit.normalize_signal(
        {
            "signal_type": "capability_gap",
            "severity": "P1",
            "case": "dubbo",
            "step": "step5",
            "symbol": "org.example.Api.call(String)",
            "expected": "reachable from bytecode",
            "actual": "not_analyzed",
            "evidence": ["alerts.csv", "summary.json"],
            "fixture_status": "missing",
        }
    )

    self.assertEqual(signal.signal_type, "capability_gap")
    self.assertEqual(signal.severity, "P1")
    self.assertTrue(signal.blocking)
    self.assertEqual(signal.evidence, ("alerts.csv", "summary.json"))
```

Add a second test:

```python
def test_audit_accepts_explicit_quality_signals_from_real_project_payload(self):
    payload = {
        "results": [
            {
                "case": "dubbo",
                "status": "passed",
                "quality_signals": [
                    {
                        "signal_type": "evidence_weakness",
                        "severity": "P2",
                        "blocking": False,
                        "step": "step5",
                        "message": "path_text lacks consumer jar",
                    }
                ],
            }
        ]
    }

    signals = quality_signal_audit.audit_real_project_payload(payload)

    self.assertEqual(len(signals), 1)
    self.assertEqual(signals[0].signal_type, "evidence_weakness")
    self.assertFalse(signals[0].blocking)
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `python3 -m unittest tests.test_quality_signal_audit`

Expected: failure because `normalize_signal` and canonical fields do not exist.

- [ ] **Step 3: Implement the canonical model**

In `scripts/quality_signal_audit.py`, replace the old dataclass with:

```python
@dataclass(frozen=True)
class QualitySignal:
    signal_type: str
    severity: str
    blocking: bool
    case: str
    step: str = ""
    symbol: str = ""
    message: str = ""
    count: int = 0
    expected: str = ""
    actual: str = ""
    evidence: tuple[str, ...] = ()
    fixture_status: str = ""
    notes: str = ""
```

Add helpers:

```python
LEGACY_KIND_TO_TYPE = {
    "real_project_skipped": "infra_skip",
    "gating_production_missing": "correctness_failure",
    "non_gating_production_missing": "capability_gap",
    "non_gating_missing_explanation": "evidence_weakness",
}

LEGACY_SEVERITY_TO_P = {
    "high": "P1",
    "medium": "P2",
    "low": "P3",
}


def _default_blocking(signal_type: str, severity: str) -> bool:
    if severity == "P0":
        return True
    if severity == "P1" and signal_type in {"correctness_failure", "capability_gap", "evidence_weakness"}:
        return True
    return False


def normalize_signal(raw: dict, default_case: str = "") -> QualitySignal:
    legacy_kind = str(raw.get("kind") or "")
    signal_type = str(raw.get("signal_type") or LEGACY_KIND_TO_TYPE.get(legacy_kind) or legacy_kind or "evidence_weakness")
    severity = str(raw.get("severity") or "P2")
    severity = LEGACY_SEVERITY_TO_P.get(severity, severity)
    evidence = raw.get("evidence") or ()
    if isinstance(evidence, str):
        evidence = (evidence,)
    else:
        evidence = tuple(str(item) for item in evidence)
    blocking = raw.get("blocking")
    if blocking is None:
        blocking = _default_blocking(signal_type, severity)
    return QualitySignal(
        signal_type=signal_type,
        severity=severity,
        blocking=bool(blocking),
        case=str(raw.get("case") or default_case),
        step=str(raw.get("step") or ""),
        symbol=str(raw.get("symbol") or ""),
        message=str(raw.get("message") or ""),
        count=int(raw.get("count") or 0),
        expected=str(raw.get("expected") or ""),
        actual=str(raw.get("actual") or ""),
        evidence=evidence,
        fixture_status=str(raw.get("fixture_status") or ""),
        notes=str(raw.get("notes") or ""),
    )
```

Update existing signal creation to use `normalize_signal({...})`.

- [ ] **Step 4: Run tests and verify they pass**

Run: `python3 -m unittest tests.test_quality_signal_audit`

Expected: all tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add scripts/quality_signal_audit.py tests/test_quality_signal_audit.py
git commit -m "Add canonical quality signal model"
```

### Task 2: Real Project Runner Emits Blocking Signals

**Files:**
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Consumes: `run_case(...) -> dict`
- Produces: `result["quality_signals"] -> list[dict]`
- Produces: `build_quality_signals(case: RealProjectCase, result_fields: dict) -> list[dict]`

- [ ] **Step 1: Write failing tests for runner-emitted signals**

Add to `tests/test_real_project_regression.py`:

```python
def test_run_case_emits_quality_signals_for_blocking_failures(self):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "project"
        report_root = Path(tmp) / "reports"
        root.mkdir()
        changed_apis = Path(tmp) / "all_changed_apis.csv"
        changed_apis.write_text(
            "coord,old_version,new_version,change_type,api_name,api_simple,symbol_kind,api_signature,confirmed,severity,source\n"
            "demo:dep,1,-,REMOVED,demo.Api.removed,removed,method,(String),true,P1,test\n",
            encoding="utf-8",
        )
        case = realreg.RealProjectCase(
            name="mini",
            default_project=root,
            default_changed_apis=changed_apis,
            baseline_specs=(
                realreg.BaselineSpec(
                    symbol="demo.Api.removed",
                    pattern=r"Api\s*\.\s*removed\s*\(",
                    import_pattern=r"import\s+demo\.Api\s*;",
                ),
            ),
        )

        def fake_run_step5(_case, _project_root, _changed_apis, report_dir):
            output = report_dir / "evidence" / "call_chain"
            output.mkdir(parents=True)
            (output / "alerts.csv").write_text("changed_symbol,evidence_files\n", encoding="utf-8")
            (output / "summary.json").write_text(
                json.dumps({"total_apis": 1, "reachable": 0, "uncertain": 0, "not_analyzed": 1}),
                encoding="utf-8",
            )
            return 0, 0.1

        with patch.object(realreg, "run_step5", side_effect=fake_run_step5):
            result = realreg.run_case(case, root, changed_apis, report_root)

    signals = result["quality_signals"]
    self.assertTrue(any(item["signal_type"] == "capability_gap" for item in signals))
    self.assertTrue(any(item["blocking"] for item in signals))
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `python3 -m unittest tests.test_real_project_regression`

Expected: failure because `quality_signals` is not emitted.

- [ ] **Step 3: Implement signal emission**

In `scripts/real_project_regression.py`, add:

```python
def make_signal(signal_type, severity, case, step="", symbol="", message="", count=0,
                expected="", actual="", evidence=(), fixture_status="missing", notes=""):
    blocking = severity in {"P0", "P1"} and signal_type in {
        "correctness_failure", "capability_gap", "evidence_weakness"
    }
    return {
        "signal_type": signal_type,
        "severity": severity,
        "blocking": blocking,
        "case": case,
        "step": step,
        "symbol": symbol,
        "message": message,
        "count": count,
        "expected": expected,
        "actual": actual,
        "evidence": list(evidence),
        "fixture_status": fixture_status,
        "notes": notes,
    }
```

Add a local `quality_signals = []` in `run_case`. Convert these existing facts:

- missing project or changed APIs -> `infra_skip`, `P1`, `blocking: false`;
- gated production missing -> `correctness_failure`, `P1`, blocking;
- non-gating production missing -> `capability_gap`, `P2`, non-blocking;
- summary `not_analyzed` > 0 -> `capability_gap`, `P1`, blocking;
- summary `uncertain` > 0 -> `capability_gap`, `P2`, non-blocking;
- `audit_analysis_outputs` failures -> `evidence_weakness`, `P1`, blocking;
- graph stat thresholds and performance thresholds -> `capability_gap`, `P1`, blocking.

Include `quality_signals` in every returned result.

- [ ] **Step 4: Run tests and verify they pass**

Run: `python3 -m unittest tests.test_real_project_regression tests.test_quality_signal_audit`

Expected: all tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add scripts/real_project_regression.py tests/test_real_project_regression.py
git commit -m "Emit real project quality signals"
```

### Task 3: Release Gate Audits Real Project Signals

**Files:**
- Modify: `scripts/quality_gate.py`
- Create: `tests/test_quality_gate.py`

**Interfaces:**
- Consumes: `quality_gate.build_plan(profile, skip_real, real_case, report_root)`
- Produces: release profile task `quality_signal_audit`
- Produces: gate JSON fields `decision`, `blocking_signals`, `non_blocking_signals`, `real_project_skipped`

- [ ] **Step 1: Write failing tests for release audit planning**

Create `tests/test_quality_gate.py`:

```python
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import quality_gate  # noqa: E402


class QualityGateTest(unittest.TestCase):
    def test_release_plan_runs_signal_audit_after_real_project_matrix(self):
        tasks = quality_gate.build_plan(
            "release",
            python_exe="python3",
            skip_real=False,
            real_case="all",
            report_root="/tmp/jua-real",
        )
        names = [task.name for task in tasks]

        self.assertIn("real_project_all", names)
        self.assertIn("quality_signal_audit", names)
        self.assertGreater(names.index("quality_signal_audit"), names.index("real_project_all"))
        audit = next(task for task in tasks if task.name == "quality_signal_audit")
        self.assertIn("--fail-on-blocking", audit.command)
```

- [ ] **Step 2: Run test and verify it fails**

Run: `python3 -m unittest tests.test_quality_gate`

Expected: failure because `quality_signal_audit` is not planned.

- [ ] **Step 3: Implement audit task planning**

In `scripts/quality_gate.py`:

- Add `json_out: str = ""` to `GateTask`.
- Add `_real_project_task(..., json_out)` so real project runs write a known JSON file when the profile needs audit.
- Add `_quality_signal_audit_task(python_exe, real_json, audit_json)`:

```python
def _quality_signal_audit_task(python_exe, real_json, audit_json):
    return GateTask(
        name="quality_signal_audit",
        command=[
            python_exe,
            "scripts/quality_signal_audit.py",
            real_json,
            "--fail-on-blocking",
            "--json-out",
            audit_json,
        ],
        purpose="审计真实项目质量信号，阻塞 P0/P1 correctness/capability/evidence 问题",
        heavy=False,
        real_project=True,
    )
```

Use deterministic paths under the provided `--report-root` or `/private/tmp/jua-quality-gate`:

```python
audit_root = Path(report_root or "/private/tmp/jua-quality-gate")
real_json = str(audit_root / f"real_project_{real_case}.json")
audit_json = str(audit_root / f"quality_signal_audit_{real_case}.json")
```

For `release`, append audit after `real_project_all` when `skip_real` is false. For `step5`, append audit when a real project task is included.

- [ ] **Step 4: Implement gate summary enrichment**

After tasks run, read the audit JSON if it exists and add:

```python
"decision": "release_blocked" if overall == "failed" else "release_allowed",
"blocking_signals": audit_summary.get("blocking_signals", 0),
"non_blocking_signals": audit_summary.get("non_blocking_signals", 0),
"real_project_skipped": audit_summary.get("by_type", {}).get("infra_skip", 0),
```

If no audit file exists, use zero values.

- [ ] **Step 5: Run tests and verify they pass**

Run: `python3 -m unittest tests.test_quality_gate tests.test_quality_signal_audit`

Expected: all tests pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add scripts/quality_gate.py tests/test_quality_gate.py
git commit -m "Gate release on quality signals"
```

### Task 4: Audit CLI Blocks on Canonical Blocking Signals

**Files:**
- Modify: `scripts/quality_signal_audit.py`
- Modify: `tests/test_quality_signal_audit.py`

**Interfaces:**
- Produces CLI flag: `--fail-on-blocking`
- Produces summary fields: `blocking_signals`, `non_blocking_signals`, `by_type`, `by_severity`

- [ ] **Step 1: Write failing CLI test**

Add:

```python
def test_cli_fail_on_blocking_exits_nonzero_only_for_blocking_signals(self):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "real.json"
        path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "case": "dubbo",
                            "status": "passed",
                            "quality_signals": [
                                {
                                    "signal_type": "capability_gap",
                                    "severity": "P1",
                                    "blocking": True,
                                    "message": "bytecode evidence exists but result is not_analyzed",
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "quality_signal_audit.py"),
                str(path),
                "--fail-on-blocking",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
        )

    self.assertNotEqual(completed.returncode, 0)
    self.assertIn('"blocking_signals": 1', completed.stdout)
```

- [ ] **Step 2: Run test and verify it fails**

Run: `python3 -m unittest tests.test_quality_signal_audit`

Expected: parser does not recognize `--fail-on-blocking`.

- [ ] **Step 3: Implement CLI flag and summary fields**

Add parser flag:

```python
parser.add_argument("--fail-on-blocking", action="store_true", help="Fail when any canonical blocking signal is present")
```

Update `summarize_signals` to return:

```python
{
    "signal_count": len(signals),
    "blocking_signals": sum(1 for signal in signals if signal.blocking),
    "non_blocking_signals": sum(1 for signal in signals if not signal.blocking),
    "by_type": dict(sorted(by_type.items())),
    "by_severity": dict(sorted(by_severity.items())),
}
```

Return 1 when `args.fail_on_blocking` and any signal has `blocking == True`.

- [ ] **Step 4: Run tests and verify they pass**

Run: `python3 -m unittest tests.test_quality_signal_audit tests.test_quality_gate`

Expected: all tests pass.

- [ ] **Step 5: Commit**

Run:

```bash
git add scripts/quality_signal_audit.py tests/test_quality_signal_audit.py
git commit -m "Block audit on canonical quality signals"
```

### Task 5: Fixture Debt Visibility

**Files:**
- Modify: `scripts/quality_signal_audit.py`
- Modify: `tests/test_quality_signal_audit.py`
- Modify: `docs/developer/quality.md`

**Interfaces:**
- Consumes: `fixture_status` on canonical signals.
- Produces summary field: `fixture_debt`.

- [ ] **Step 1: Write failing fixture debt summary test**

Add:

```python
def test_summary_counts_blocking_fixture_debt(self):
    signals = [
        quality_signal_audit.normalize_signal(
            {
                "signal_type": "correctness_failure",
                "severity": "P1",
                "blocking": True,
                "case": "dubbo",
                "fixture_status": "missing",
            }
        ),
        quality_signal_audit.normalize_signal(
            {
                "signal_type": "capability_gap",
                "severity": "P2",
                "blocking": False,
                "case": "seata",
                "fixture_status": "planned",
            }
        ),
    ]

    summary = quality_signal_audit.summarize_signals(signals)

    self.assertEqual(summary["fixture_debt"], 1)
```

- [ ] **Step 2: Run tests and verify they fail**

Run: `python3 -m unittest tests.test_quality_signal_audit`

Expected: `fixture_debt` is absent.

- [ ] **Step 3: Implement fixture debt count**

In `summarize_signals`, count blocking signals whose `fixture_status` is empty or `missing`:

```python
fixture_debt = sum(
    1 for signal in signals
    if signal.blocking and signal.fixture_status in {"", "missing"}
)
```

Add it to the returned summary.

- [ ] **Step 4: Document the workflow**

In `docs/developer/quality.md`, add a short section:

```markdown
## Fixture Debt

Every P0/P1 real-project signal must be converted into an L0/L1/L2 regression,
marked as planned with a concrete fixture shape, or waived with a reason and
expiry. Release gates count missing fixture coverage as fixture debt.
```

- [ ] **Step 5: Run tests and docs checks**

Run:

```bash
python3 -m unittest tests.test_quality_signal_audit
git diff --check
```

Expected: tests pass and diff check prints no errors.

- [ ] **Step 6: Commit**

Run:

```bash
git add scripts/quality_signal_audit.py tests/test_quality_signal_audit.py docs/developer/quality.md
git commit -m "Track fixture debt in quality audit"
```

### Task 6: Final Verification

**Files:**
- Modify only if previous tasks reveal gaps.

**Interfaces:**
- Consumes all previous task outputs.
- Produces verified gate commands.

- [ ] **Step 1: Run focused tests**

Run:

```bash
python3 -m unittest tests.test_quality_signal_audit tests.test_real_project_regression tests.test_quality_gate
```

Expected: all tests pass.

- [ ] **Step 2: Run quick gate dry-run**

Run:

```bash
python3 scripts/quality_gate.py --profile release --skip-real --dry-run
```

Expected: output includes normal release tasks and omits real-project audit when `--skip-real` is present.

- [ ] **Step 3: Run diff check**

Run:

```bash
git diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 4: Inspect status**

Run:

```bash
git status --short
```

Expected: only intentional files modified; unrelated pre-existing files remain untouched.

- [ ] **Step 5: Commit any final documentation or cleanup**

Run:

```bash
git add docs/superpowers/plans/2026-07-10-real-project-testing-redesign.md
git commit -m "Plan real project testing implementation"
```

Skip this commit if the plan document was already committed before implementation began.
