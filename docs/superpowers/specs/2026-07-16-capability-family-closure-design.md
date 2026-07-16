# Capability Family Closure Design

## Goal

Turn real-project findings into architecture-level capability improvements. A finding may close only when the affected capability invariant is enforced across every declared production path and by generalized executable tests; a project-specific fix is never sufficient.

## Problem

The current retrospective gate rejects `resolution_scope=case_patch`, but a review can still claim `architecture` or `evidence_model` without proving that parallel source, bytecode, nested-JAR, framework, and Oracle paths were audited. This makes the gate primarily documentary. It does not prevent a fix from covering one branch while an equivalent branch remains defective.

Real projects must remain discovery probes. They must not become the unit of implementation. The unit of implementation is a stable capability family with one explicit invariant.

## Architecture

### Capability Family Registry

Add a versioned registry at `tests/fixtures/capability_families.json`. Each family declares:

- a stable family identifier;
- one falsifiable engineering invariant;
- every production path that can create, normalize, transport, or adjudicate that evidence;
- generalized positive, negative, boundary, and mutation tests;
- representative real-project guards when a final artifact is required;
- whether a repeated finding requires an architecture decision.

The first registry covers the existing root-cause taxonomy. Families without executable closure evidence remain `open`; they cannot be treated as fixed merely because no current project reports them.

### Closure Ledger

Extend each reviewed finding with:

- `capability_family`;
- `invariant_id`;
- `audited_production_paths`;
- `generalized_regression_tests`;
- `negative_regression_tests`;
- `mutation_tests`;
- `cross_project_guards`;
- `architecture_decision` when the family repeats.

The values must reference registry entries exactly. A P0/P1 finding with `status=fixed` is invalid unless every registered production path is audited, every required test reference resolves, every required real-project guard passed in the current result payload, and any repeated family has an architecture decision.

### Executable Closure Gate

Create `scripts/capability_family_closure.py` as a pure validator and CLI. It consumes the registry, real-project result, retrospective review ledger, and optional history. It emits a deterministic JSON report and returns nonzero for incomplete closure.

The gate does not trust review text as proof. It verifies paths exist, unittest references load, required test categories are non-empty, referenced current real-project guards passed, and declared path coverage equals the registry path set. It also rejects extra path names so misspellings cannot appear as coverage.

`scripts/quality_gate.py --profile step5|release` runs this gate after the retrospective. A failed real-project matrix still produces a closure report, but closure remains blocked.

### Generalized Invariant Tests

The first executable invariant suite targets the repeated artifact identity and ownership family. The same logical call graph is packaged as:

1. business classes plus an external dependency JAR;
2. a normal internal module JAR;
3. a Spring Boot nested internal module under `BOOT-INF/lib`;
4. two runtime JARs sharing a logical coordinate;
5. the same layouts with an unrelated same-named owner.

The analyzer must preserve canonical API identity and physical edges across equivalent layouts while preserving the correct ownership provenance. Removing a nested entry, changing owner/descriptor, supplying a stale class directory, or changing the final-artifact SHA must fail closed rather than produce a false negative or reachable conclusion.

These are generated fixture tests, not project-name assertions. Existing real projects remain cross-project guards for the invariant.

## Data Flow

1. A real project produces a quality signal.
2. The retrospective assigns a root-cause family.
3. The closure gate resolves that family to one registry invariant.
4. The review declares all audited production paths and generalized tests.
5. The gate compares declarations with executable registry requirements and current real-project results.
6. Only a complete match allows the finding to close.
7. A repeated family without a new architecture decision blocks project rotation.

## Failure Semantics

- Missing or invalid registry: fail closed.
- Unknown family or invariant: fail closed.
- Missing production path: fail closed.
- Missing, unloadable, or wrongly categorized test: fail closed.
- Missing or non-passing cross-project guard: fail closed.
- Repeated family without architecture decision: fail closed.
- Real-project input unavailable: emit `blocked`, never infer success.
- P2/P3 accepted uncertainty may remain open, but it cannot be reported as a fixed capability.

## Boundaries

- The registry is development-test policy and must not be copied into `SKILL.md` or `RUNBOOK.md`.
- The gate does not decide analyzer conclusions and cannot be used as an Oracle.
- Test counts and pass percentages are diagnostic only; they are not closure evidence by themselves.
- No new real project is added until the current repeated capability families have executable closure evidence.

## Success Criteria

- A project-specific fixed review with incomplete path coverage is rejected.
- Renaming a case patch to `architecture` without generalized tests is rejected.
- Removing any required positive, negative, mutation, or cross-project guard reopens the family.
- The artifact identity and ownership invariant runs across all declared packaging forms.
- Step5 and release quality gates invoke capability closure automatically.
- A new project finding maps to an existing family or explicitly creates a reviewed new invariant; it never directly creates another conditional production patch.
