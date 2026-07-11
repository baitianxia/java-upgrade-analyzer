# Real Project Testing V2

Date: 2026-07-11

## Problem

The first real-project redesign still allowed a large project to create false
confidence. The Dubbo case found 5,440 changed APIs but selected only 9 for
Step5, a coverage ratio of 0.17%. Its runner reported `passed` even when the
independent audit contained a blocking capability gap. A subsequent full run
produced 2,680 reachable and 2,760 not-analyzed P0 APIs, including 2,367 cases
without runtime dependency jars and 393 overload-ambiguous targets.

Project size is not coverage. A real-project run is useful only when its tested
surface, evidence readiness, conclusion quality, accuracy evidence, and
performance envelope are explicit and independently gated.

## Decision

Use a dual-track matrix:

- discovery cases analyze the complete Step4 API population and exist to find
  new failure classes;
- guard cases run a smaller declared probe set only after discovered failures
  have stable repository fixtures.

Both tracks use the same structured audit. A guard case cannot be presented as
evidence for APIs outside its declared probes. A discovery case cannot pass
unless every selected Step4 API is accounted for by Step5.

## Case Lifecycle

Every case declares one lifecycle state:

- `discovery`: full API coverage is mandatory and new findings are expected;
- `convergence`: full coverage remains mandatory while P0/P1 findings are
  converted into fixtures;
- `guard`: representative probes protect already understood failure classes.

The result records `case_mode`, `api_population`, `apis_selected`,
`coverage_ratio`, and `coverage_scope`. For discovery and convergence,
`coverage_scope` must be `full` and `coverage_ratio` must be 1.0. For guard,
the result must state `declared_probes`; no report may imply project-wide
coverage.

## Five Independent Gates

### Coverage Gate

The runner compares Step4's complete API population with the actual Step5
input. It emits `coverage_gap` when:

- a discovery or convergence case selects fewer APIs than Step4 produced;
- selected API identities are missing from Step5 output;
- Step5 output totals do not equal selected input totals.

`coverage_gap` is P1 and blocking. A zero-API population is valid only when
Step4 evidence proves that no API changes exist.

### Evidence Readiness Gate

Before Step5, the runner records availability of:

- project source and valid Git history;
- old and current target artifacts;
- runtime dependency jars;
- dependency source mappings;
- exact API signatures.

Missing evidence is not one generic skip. Affected APIs are grouped by
`reason_code`, `symbol_kind`, and evidence mode. Required evidence that is
available to the test harness but not supplied to the analyzer is
`test_configuration_failure`; evidence that the analyzer could derive but does
not is `capability_gap`; genuinely unavailable external evidence is
`infra_skip` and cannot count as coverage success.

### Conclusion Gate

Every selected API must end in exactly one Step5 state. P0/P1 `not_analyzed`,
unexpected `uncertain`, and unexpected `not_found_in_static_analysis` are
blocking. Signals are emitted per reason group and include representative
symbols, counts, and evidence paths.

The case status is derived after signals are built:

- `failed` when any blocking signal exists;
- `skipped` only when no semantic analysis ran because infrastructure was
  unavailable;
- `passed` only when no blocking signal exists;
- `observed` for discovery data that completed but lacks enough ground truth
  to claim accuracy. `observed` blocks release.

The textual runner status and audit decision must never disagree.

### Accuracy Gate

Large result sets require deterministic stratified ground truth. Sampling uses
a stable hash of case, pinned commit, API identity, and result state. Samples
cover each combination of:

- Step5 state;
- symbol kind: class, constructor, method, field;
- reason code;
- direct source, transitive source, bytecode, reflection, and fallback match;
- production and test source.

Each stratum samples at least 10 items or all items when smaller. P0 reachable
items with fallback matching receive an additional sample. Ground truth must
use exact owner and signature evidence from parsers, compiled bytecode, or
manually reviewed manifests; broad grep is discovery evidence only.

The result reports reviewed count, false positives, false negatives,
unsupported conclusions, and Wilson confidence bounds. Until the initial
manifest exists, the case is `observed`, not `passed`.

### Performance Gate

Performance is evaluated without reducing coverage. Each case records and
gates:

- Step4 and Step5 wall time;
- Step5 time per 1,000 selected APIs;
- potential method-target pairs and pairs per selected API;
- owner-presence scans;
- trace incoming edges scanned;
- report generation time;
- graph truncation and edge-cap hits;
- peak resident memory when the platform exposes it.

Budgets have an absolute ceiling and a regression ceiling against a pinned
baseline. A metric over either ceiling emits `performance_regression`. The
Dubbo discovery baseline must explicitly track the observed 143,240,640
potential method-target pairs; this metric may not disappear from reports.

## Signal Model

The canonical signal types add:

- `coverage_gap`;
- `test_configuration_failure`;
- `ground_truth_insufficient`;
- `conclusion_gap`;

Existing `correctness_failure`, `capability_gap`, `evidence_weakness`,
`performance_regression`, `project_asset_invalid`, and `infra_skip` remain.

Signals must include `reason_code`, `symbol_kind`, `count`,
`sample_symbols`, `expected`, `actual`, `evidence`, and `fixture_status` when
those fields apply. Aggregate signals may group only semantically equivalent
items. A single aggregate signal may not combine missing jars with overload
ambiguity.

## Fixture Lifecycle

Fixture debt is keyed by:

`case + reason_code + symbol_kind + evidence_mode`.

Every blocking group must be `missing`, `planned`, `implemented`, or `waived`.
A waiver includes owner, reason, and expiry. A discovery case moves to guard
only when all P0/P1 groups are implemented or have unexpired waivers. Once a
case becomes guard-only and yields no new groups for three full runs, discovery
capacity rotates to a project with a different architecture or evidence mode.

## Release Rules

A release is blocked when any included case has:

- incomplete or undeclared coverage;
- blocking semantic signals;
- insufficient ground truth;
- invalid or missing required test evidence;
- an exceeded absolute or regression performance budget;
- unresolved fixture debt;
- `observed`, `failed`, or `skipped` status.

Release output reports project coverage and ground-truth coverage separately.
Passing repository fixtures does not substitute for a required discovery run,
and a discovery run does not substitute for stable fixtures.

## Initial Implementation Scope

The first implementation slice changes the current runner and audit to:

1. declare case lifecycle and compute API coverage;
2. emit blocking coverage gaps;
3. group not-analyzed results by reason code and symbol kind;
4. derive runner status from blocking signals;
5. expose normalized performance metrics and candidate-pair budgets;
6. mark cases without ground-truth manifests as `observed`.

Deterministic sample manifest generation and reviewed-manifest ingestion follow
as the second slice. The first slice must not claim accuracy before that second
slice exists.

## Acceptance Baseline

For the existing full Dubbo result:

- API population and selected APIs are both 5,440;
- coverage ratio is 1.0;
- 2,760 not-analyzed APIs produce at least two separate blocking groups:
  `RUNTIME_DEPENDENCY_JARS_UNAVAILABLE` and `OVERLOAD_AMBIGUOUS_TARGET`;
- the case status is `failed`, never `passed`;
- 143,240,640 potential method-target pairs are present in performance output;
- without reviewed ground truth, no accuracy-pass claim is emitted.

