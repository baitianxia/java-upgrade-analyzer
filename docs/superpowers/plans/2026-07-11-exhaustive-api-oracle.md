# Exhaustive Per-API Oracle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Require an independent correctness verdict for every API analyzed by a real-project discovery case.

**Architecture:** A focused `exhaustive_api_oracle.py` module builds canonical API identities, joins Step5 conclusions with third-party authority records, writes one ledger row per selected API, and rejects missing, duplicate, extra, incorrect, unverifiable, conflicting, or self-certified rows. `real_project_regression.py` invokes it and converts its exhaustive summary into release-blocking signals; repository code may aggregate authority evidence but cannot certify itself.

**Tech Stack:** Python 3 standard library, CSV/JSON, `unittest`.

## Global Constraints

- Sampling cannot authorize release.
- Every selected API identity must appear exactly once in the ledger.
- Analyzer output cannot serve as its own oracle.
- Every `correct` verdict requires third-party authority provenance.
- Dynamic-call and negative P0/P1 verdicts require two independent authorities or one executable project-test authority.
- Conflicting authorities block; majority voting is forbidden.
- `incorrect`, `unverified`, and `oracle_conflict` block per API.
- Aggregate display never replaces the per-API ledger.

---

### Task 1: Canonical Identity and Exhaustive Join

**Files:**
- Create: `scripts/exhaustive_api_oracle.py`
- Create: `tests/test_exhaustive_api_oracle.py`

**Interfaces:**
- Produces: `canonical_identity(row: dict) -> str`
- Produces: `audit_api_oracle(changed_rows: list[dict], analyzer_rows: list[dict], oracle_rows: list[dict]) -> dict`

- [ ] **Step 1: Write failing identity and completeness tests**

Test exact owner, signature, and symbol kind identity; one correct third-party record; one self-certified record becoming `unverified`; one missing record becoming `unverified`; duplicate and extra identities becoming blocking errors; conflicting authorities becoming `oracle_conflict`.

- [ ] **Step 2: Run tests and verify failure**

Run: `python3 -m unittest tests.test_exhaustive_api_oracle`

- [ ] **Step 3: Implement the minimal exhaustive join**

Validate `authority`, `authority_version`, `procedure`, `evidence_path`,
`evidence_sha256`, and `generated_at`. Return `ledger`, `selected`, `verified`, `incorrect`, `unverified`,
`oracle_conflicts`, `missing_identities`, `duplicate_identities`,
`extra_identities`, `invalid_provenance`, and `blocking`.

- [ ] **Step 4: Run tests and verify pass**

Run: `python3 -m unittest tests.test_exhaustive_api_oracle`

- [ ] **Step 5: Commit**

```bash
git add scripts/exhaustive_api_oracle.py tests/test_exhaustive_api_oracle.py
git commit -m "Add exhaustive per-API oracle audit"
```

### Task 2: Ledger Files and Real-Project Integration

**Files:**
- Modify: `scripts/exhaustive_api_oracle.py`
- Modify: `scripts/real_project_regression.py`
- Modify: `tests/test_exhaustive_api_oracle.py`
- Modify: `tests/test_real_project_regression.py`

**Interfaces:**
- Produces: `load_analyzer_rows(summary: dict) -> list[dict]`
- Produces: `load_oracle_manifest(path: Path) -> list[dict]`
- Produces: `write_oracle_ledger(path: Path, audit: dict) -> None`
- Adds `RealProjectCase.oracle_manifest: Path | None`

- [ ] **Step 1: Write failing I/O and integration tests**

Assert all five Step5 state lists load into analyzer rows, CSV manifest parsing preserves authority provenance, and an unconfigured two-API discovery case writes two `unverified` ledger rows plus a blocking `ground_truth_insufficient` signal with count 2.

- [ ] **Step 2: Run tests and verify failure**

Run: `python3 -m unittest tests.test_exhaustive_api_oracle tests.test_real_project_regression`

- [ ] **Step 3: Implement ledger I/O and runner integration**

Write `evidence/quality/exhaustive_api_oracle.csv`. Replace the generic ground-truth signal with counts from the exhaustive audit. Include `oracle_audit` and `oracle_ledger` in each result.

- [ ] **Step 4: Run tests and verify pass**

Run: `python3 -m unittest tests.test_exhaustive_api_oracle tests.test_real_project_regression tests.test_quality_signal_audit`

- [ ] **Step 5: Commit**

```bash
git add scripts/exhaustive_api_oracle.py scripts/real_project_regression.py tests/test_exhaustive_api_oracle.py tests/test_real_project_regression.py
git commit -m "Integrate exhaustive oracle into real project gate"
```

### Task 3: Release Verification

**Files:**
- Modify: `tests/test_quality_gate.py`

**Interfaces:**
- Consumes exhaustive oracle signals and result fields.

- [ ] **Step 1: Add release tests**

Assert release fails when any ledger row is missing, incorrect, unverified, conflicting, self-certified, invalid-provenance, duplicate, or extra, and passes only when verified equals selected with all error counts zero and all verdicts have valid third-party provenance.

- [ ] **Step 2: Run focused and complete tests**

Run:

```bash
python3 -m unittest tests.test_exhaustive_api_oracle tests.test_real_project_regression tests.test_quality_signal_audit tests.test_quality_gate
python3 -m unittest discover -s tests -p 'test_*.py'
```

- [ ] **Step 3: Validate Dubbo evidence**

Generate the ledger from the saved 5,440-API Dubbo result and verify `selected=5440`, `verified=0`, `unverified=5440`, `blocking=true` until independent oracle records exist.

- [ ] **Step 4: Commit**

```bash
git add tests/test_quality_gate.py
git commit -m "Gate releases on exhaustive oracle completeness"
```
