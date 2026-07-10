# Real Project Testing Redesign

Date: 2026-07-10

## Purpose

The current test suite can pass while obvious failures still appear when the
skill is used on real Java projects. The redesigned test strategy must find
those failures before users do.

The goal is not only to detect classic false negatives and false positives. The
test system must also expose capability gaps: cases where the current analyzer
returns a conservative or weak result, but stronger engineering could produce a
more precise, more useful, or more reviewable conclusion from available source,
bytecode, dependency, or build evidence.

## Design Principles

- Real projects are problem finders. Repository fixtures are regression locks.
- A passing test must mean the analyzer produced useful and reviewable evidence,
  not merely that scripts exited successfully.
- Every new real-project failure or important capability gap must be converted
  into a stable in-repository fixture or tracked as explicit fixture debt.
- Unknown, skipped, uncertain, and not analyzed results must be visible in
  release decisions. They cannot be hidden behind an overall `passed` status.
- Accuracy takes priority over speed. Performance checks must detect accidental
  complexity regressions, but performance work cannot reduce analysis coverage.

## Testing Architecture

The testing system has three cooperating lines.

### Reproducible Regression Line

This line runs inside the repository and is suitable for normal CI:

- unit tests for specific parsing, matching, graph, and output contracts;
- generated Java fixtures with real `javac` output and real jars;
- end-to-end user scenarios that simulate actual skill usage;
- accuracy benchmark categories aligned to real failure modes.

This line is the long-term guardrail. Whenever a real project reveals a new
problem, the fix is incomplete until this line contains a stable reproduction.

### Real Open-Source Project Matrix

This line runs against fixed open-source Java projects. It detects combinations
that synthetic tests did not anticipate: multi-module builds, dense utility
classes, overloaded APIs, dependency jars, mixed production/test sources,
framework migration patterns, and large call graphs.

The matrix is not allowed to report only passed or failed. It must emit
structured quality signals that separate correctness failures, capability gaps,
evidence weaknesses, and infrastructure skips.

### Quality Signal Audit Line

This line audits all test outputs after the underlying scripts finish. It
prevents weak conclusions from being treated as success. For example, a real
project run that completes but produces many unexpected `not_analyzed` results,
tiny graph statistics, missing evidence files, or skipped cases must be flagged
even if the runner returned zero.

## Test Layers

### L0: Focused Semantic Regressions

Scope:

- owner and import resolution;
- static imports and fields;
- overload and signature matching;
- assignable parameters and varargs;
- constructors, fields, default methods, static interface methods;
- reflection, `MethodHandle`, expression language, and string-based references;
- four/five-state Step5 conclusion semantics;
- Step6 report classification and evidence rendering.

Rules:

- Add positive and negative tests together whenever a matching capability is
  expanded.
- A negative test must be close enough to the positive case to catch overbroad
  fixes.
- Tests should assert semantic outputs, not incidental implementation details.

### L1: Generated Java Fixture Regressions

Scope:

- repository-generated Java projects;
- real compiled classes;
- real jars, nested jars, and runtime dependency jars;
- source-present and source-missing modes;
- deleted dependency, upgraded dependency, and changed member cases;
- cross-jar paths such as business -> dep-a -> dep-b -> changed API.

Purpose:

L1 is the primary stable approximation of real user projects. It should grow
whenever L4 finds a new failure shape.

Required scenario families:

- direct business source call to changed API;
- business bytecode call to dependency jar that calls changed API;
- multi-hop runtime dependency chain;
- same simple class name with different owners;
- same method name with incompatible overloads;
- field access with conflicting imports;
- source unavailable but bytecode sufficient;
- source available but bytecode is the authoritative runtime fact;
- reflection and MethodHandle candidates that must become `reachable` or
  `uncertain`, not silent misses;
- cases where `not_impacted` requires positive evidence from the current
  artifact.

### L2: User Scenario Regressions

Scope:

- end-to-end flows that resemble user interaction;
- generated workspaces under a temporary directory;
- Step4/Step5/Step6 contracts that users depend on;
- follow-up query workflows after Step5.

Required checks:

- the final report points to the relevant evidence files;
- query results can explain a reachable chain;
- rerun behavior does not mix old and new artifacts;
- target module and final artifact assumptions remain explicit;
- output contracts remain stable for downstream review.

### L3: Accuracy Benchmark Matrix

Scope:

`accuracy_benchmark.py` should remain the quick way to run high-risk semantic
contracts, but its categories should be aligned to these risk groups:

- false negative risk;
- false positive risk;
- capability gap risk;
- evidence quality risk;
- performance and scale risk.

The matrix should make clear which risks are covered and which are currently
uncovered. A green benchmark is not allowed to imply full safety outside its
declared scope.

### L4: Real Open-Source Project Matrix

Scope:

Run fixed probes against selected real projects. Initial project shapes:

- Apache Commons Text or a similarly small project for commons-lang3 utility
  methods, fields, varargs, and assignable signatures.
- Apache Dubbo or a similarly large multi-module project for dense utility
  classes, overloads, owner precision, large graph behavior, and performance.
- Apache Seata or a similarly complex application framework for production vs
  test source separation and same-name utility classes.
- A Spring Boot 2 to 3 style project for `javax` to `jakarta`, Spring
  configuration, auto-configuration, and framework migration rules.
- A Maven multi-module application-style project for Step1 through Step6,
  deployment module selection, final artifact analysis, and runtime dependency
  graph validation.

Each case must define:

- repository URL;
- pinned commit SHA;
- expected license compatibility for test use;
- local checkout path or cache key;
- project scale baseline: modules, source files, dependencies;
- probe API rows or a way to generate them;
- expected reachable, non-reachable, uncertain, and capability-gap probes;
- production/test source classification rules;
- minimum graph statistics;
- maximum expected elapsed time for relevant steps;
- allowed and disallowed quality-signal thresholds.

The real project matrix may depend on cached local checkouts for normal local
runs. Missing checkout, missing JDK, missing Maven, or missing probe artifacts
must be reported as `infra_skip`, not success.

### L5: Release Quality Audit

Scope:

Aggregate outputs from L0 through L4 and decide whether a release is acceptable.

The release audit must include:

- number of blocking signals;
- number of non-blocking signals;
- fixture debt count;
- real project skipped count;
- distribution of Step5 conclusions;
- graph-size and performance anomalies;
- evidence-file completeness;
- trend from previous known-good baseline when available.

## Quality Signal Model

Every test runner that performs semantic validation should be able to emit
quality signals with this shape:

```json
{
  "signal_type": "correctness_failure",
  "severity": "P1",
  "blocking": true,
  "case": "dubbo",
  "step": "step5",
  "symbol": "org.example.Foo.bar(String)",
  "expected": "reachable production path or uncertain with bytecode evidence",
  "actual": "not_found_in_static_analysis",
  "evidence": [
    ".upgrade-report/evidence/call_chain/alerts.csv",
    ".upgrade-report/evidence/call_chain/summary.json"
  ],
  "fixture_status": "missing"
}
```

Allowed `signal_type` values:

- `correctness_failure`: the analyzer conclusion is wrong or unsafely
  overconfident.
- `capability_gap`: the current result is conservative or weak, but available
  evidence indicates the analyzer should be able to produce a stronger result.
- `evidence_weakness`: the conclusion may be acceptable, but the output is not
  reviewable enough for users.
- `infra_skip`: the test did not run because required external infrastructure
  was unavailable.

Severity:

- `P0`: must block every profile that includes the test.
- `P1`: blocks release and any relevant Step-specific gate.
- `P2`: non-blocking for quick gates, visible in release summary, must have an
  owner or backlog entry.
- `P3`: informational trend or hygiene issue.

## Blocking Rules

Correctness failures:

- P0 and P1 always block release.
- A production baseline reference that disappears from `alerts.csv` is at least
  P1 unless the case explicitly expects no static evidence.
- A false positive caused by wrong owner, wrong overload, or simple-name fallback
  is at least P1.
- Reporting unknown or unanalyzed impact as no impact is P0.

Capability gaps:

- P0/P1 capability gaps block release when the missing ability is essential to
  the advertised purpose of the skill.
- A result of `not_analyzed` is a P1 capability gap when source, bytecode, or
  dependency evidence exists and the analyzer has a known strategy to use it.
- A low-quality `uncertain` is a P1 capability gap when a complete reachable path
  can be derived from available compiled artifacts.
- P2 capability gaps do not block quick gates but must appear in release output
  and fixture debt.

Evidence weaknesses:

- Missing primary evidence files are P1.
- Missing path details, consumer jar names, or review reasons are P1 if a human
  cannot reproduce the conclusion from the output.
- Formatting or navigation weaknesses are P2/P3 unless they hide the conclusion.

Infrastructure skips:

- A quick local gate may tolerate real-project `infra_skip` if the profile does
  not require external projects.
- A release gate cannot treat skipped real-project cases as success.
- Release should block when required real-project coverage falls below the
  configured minimum.

## Fixture Debt Policy

Every L4 blocking signal and every accepted P1 capability gap must end in one
of these states:

- `implemented`: an L0, L1, or L2 regression exists.
- `planned`: the gap is documented with a target fixture shape.
- `waived`: the signal is intentionally not reproducible in-repository, with a
  reason and expiration.

Release should block if there is untriaged P0/P1 fixture debt.

## Real Project Probe Method

For each real project case, the runner should:

1. Verify prerequisites and report `infra_skip` if they are missing.
2. Collect source-shape metrics such as Java file count, static imports,
   reflection patterns, lambdas, and framework-specific constructs.
3. Prepare or select Step4 changed API rows.
4. Run the relevant analyzer step or full pipeline.
5. Parse `summary.json`, `alerts.csv`, split alert files, Step6 findings, timing
   CSVs, and graph metadata.
6. Compare production and test baselines separately.
7. Emit structured signals instead of only failed assertions.
8. Write a per-case JSON result that `quality_signal_audit.py` can inspect
   independently.

The runner should prefer deterministic pinned inputs. It may support optional
refresh commands for maintainers, but normal gates must not depend on live
upstream changes.

## Quality Gate Profiles

Suggested profile semantics:

### quick

Runs:

- py compile;
- core accuracy benchmark;
- focused semantic tests;
- core smoke;
- selected L1 scenarios that do not require external checkouts.

Purpose:

Fast local confidence. It should catch obvious correctness regressions but does
not claim full real-project safety.

### step5

Runs:

- Step5 accuracy benchmark;
- Step5 semantic tests;
- source and bytecode graph fixtures;
- user scenario regression;
- optional real project case when available.

Purpose:

Required after changes to call-chain, bytecode, source analysis, evidence output,
or Step5 conclusion semantics.

### release

Runs:

- full accuracy benchmark;
- full unittest discovery;
- all smoke scenarios;
- all user scenarios;
- required real project matrix;
- quality signal audit;
- fixture debt audit;
- diff check.

Purpose:

Decide whether the skill can be handed to users.

## Reporting Contract

`quality_gate.py` should produce a machine-readable summary:

```json
{
  "profile": "release",
  "status": "failed",
  "decision": "release_blocked",
  "blocking_signals": 2,
  "non_blocking_signals": 5,
  "fixture_debt": 3,
  "real_project_skipped": 1,
  "results": []
}
```

`quality_signal_audit.py` should be able to read raw outputs from real project
runs and independently produce:

- blocking signal list;
- non-blocking signal list;
- skipped coverage summary;
- conclusion distribution summary;
- graph and timing anomaly summary;
- fixture debt summary.

Human-readable output should lead with the release decision and the blocking
signals. Detailed metrics should remain available in JSON.

## Migration From Current Repository State

The repository already contains several useful pieces:

- `accuracy_benchmark.py` for grouped semantic checks;
- `quality_gate.py` for profile orchestration;
- `real_project_regression.py` for Commons Text, Dubbo, and Seata style probes;
- `quality_signal_audit.py` for auditing real-project outputs;
- `user_scenario_regression.py` for generated user-like scenarios;
- detailed Step5 and Step6 semantic unit tests.

The redesign should evolve these assets instead of replacing them wholesale.

Required changes:

- extend real project results from passed/failed to structured quality signals;
- make capability gaps a first-class signal type;
- make skipped real-project coverage visible in release decisions;
- add fixture debt tracking;
- add missing L1 fixture families discovered from real projects;
- align benchmark categories with false negative, false positive, capability
  gap, evidence quality, and performance risks;
- make `quality_gate.py --profile release` run the audit and fail on blocking
  signals.

## Non-Goals

- Do not require live network access for normal CI runs.
- Do not make every local quick test clone or build large open-source projects.
- Do not treat GitHub access as mandatory for the core test design.
- Do not replace semantic tests with golden output snapshots only.
- Do not accept broad grep baselines as proof of analyzer correctness when owner
  or signature precision matters.

## Success Criteria

The redesign is successful when:

- obvious real-project failures become blocking signals before release;
- every P0/P1 real-project finding is either fixed, waived with an expiry, or
  tied to fixture debt;
- recurring failures are represented by stable repository fixtures;
- release output clearly states whether the skill is safe to hand to users;
- users no longer become the primary discovery mechanism for false negatives,
  false positives, or high-value capability gaps.
