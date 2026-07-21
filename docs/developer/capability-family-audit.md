# Capability Family Audit

This audit records architecture capability closure. It is development evidence, not analyzer runtime guidance.

## Validation Boundary

The implementation descriptions below were reconciled against `main@69b60af` on
2026-07-21. The real-project results in this document were last recorded by
`616df58` on 2026-07-16; they are historical evidence for that commit, not a
fresh guard result or release authorization for the current HEAD. A current
`closed` claim requires a new release profile with the complete `guard` (or
`all`) selector and a passing quality-signal audit.

## Status Vocabulary

- `open`: the invariant or its executable evidence is incomplete.
- `enforced`: the shared implementation boundary and generalized tests exist.
- `guard blocked`: implementation evidence exists, but one or more mandatory current real-project guards did not pass.
- `closed`: reserved for a closure report that validates all registered paths, tests, mutations, and current guards. The registry itself never claims this state.

## Current Audit

| Capability family | Implementation state at `69b60af` | Last recorded guard evidence (`616df58`) | Missing current closure evidence |
|---|---|---|---|
| `artifact_identity_ownership` | enforced | five-project guard passed | rerun the complete current guard and quality audit |
| `canonical_evidence_identity` | enforced | five-project guard passed | rerun the complete current guard and quality audit |
| `evidence_completeness_visibility` | enforced | five-project guard passed | rerun the complete current guard and quality audit |
| `framework_activation_semantics` | enforced | Dubbo reflection and two MyBatis guards passed | rerun the complete current guard and quality audit |
| `closed_world_pipeline` | enforced | formal Step5 gate passed | rerun API coverage, edge truth, conclusion, performance, fixture debt, retrospective, and capability closure together |
| `reproducible_test_assets` | enforced | materialization plans valid; five pinned guards passed | rematerialize assets and rerun the complete current guard |
| `performance_without_scope_loss` | enforced | five-project guard passed | rerun the scope and performance envelopes against current artifacts |

## Artifact Identity And Ownership Finding

The audit found a shared architecture defect: `build_runtime_dependency_catalog()` treated a nested dependency as application-owned when its Maven `groupId` matched the outer application. Group identity does not prove reactor ownership and can classify an external library as an internal business module.

The corrected invariant requires all of the following:

1. the exact `groupId:artifactId` is present in pinned project scope;
2. the nested JAR has a concrete entry in the verified current final artifact;
3. the ownership record carries the current final-artifact SHA-256;
4. the coordinate in the evidence matches the catalog item;
5. the evidence survives catalog, bytecode scan, hit, graph edge, and typed evidence projection.

The RuoYi full-artifact audit exposed a second path through the same capability
family: a direct Step5 invocation had no orchestrator state, so the catalog lost
the reactor ownership set. The fallback now reconstructs that set only when the
SHA-verified final artifact declares its own Maven coordinate and the same exact
coordinate exists in a discovered source reactor. The target module's reactor
dependency closure is then used as ownership input. A same-group nested JAR that
is absent from the reactor remains external.

Generalized tests cover a valid reactor module, missing-state reactor recovery,
a same-group external dependency in both state and recovery paths, a bare forged
ownership flag, a mismatched reactor coordinate, and a real classfile inner-bridge
scan. These tests are not tied to a production project name.

The `616df58` RuoYi guard passed all 2,185 APIs with an independent Oracle result
of 2,185 verified, zero unverified/incorrect/conflicting conclusions, 313 analyzer
and 313 Oracle physical edges, and a successful removed-edge fault injection.

The restored `gs-multi-module` checkout and deterministic final artifact passed
the same-coordinate cross-project guard at `616df58`. The 2026-07-16 formal
Step5 gate also passed capability-family closure for the registered production paths. This is
historical closure evidence for that commit, not current HEAD evidence and not a
claim that unseen Java framework topologies cannot expose new defects.

## Closed-World Pipeline Finding

The output audit previously compared only API name, signature, and symbol kind.
It ignored dependency coordinate and change type, collapsed duplicate Step4 rows
through a set, and compared `summary.json` only by total count. Two different
changes could therefore collapse into one identity, while an equal-count
missing/extra substitution in the summary still passed.

Alerts and summary entries now carry the shared canonical API identity. The
real-project gate compares the complete Step4, Step5 summary, and alert identity
sets, and separately rejects missing, extra, and duplicate identities. The
independent Oracle gate reports missing analyzer identities and duplicate Step4
identities explicitly instead of relying on an indirect incorrect verdict.

Generalized tests cover an identical closed set, same symbol under different
coordinates, duplicate Step4 identities, equal-count summary substitution,
missing analyzer output, and duplicate changed input. The `616df58` guard added
orthogonal reflection, same-coordinate multi-module, Fat Jar callback, MyBatis
annotation proxy, and MyBatis XML mapping topologies; all declared APIs passed
the closed-set and conclusion contracts in that run.

## Reproducible Asset Finding

Pinned manifests previously proved only the bytes present on one machine. They
did not state how to recreate those bytes, two published MyBatis artifacts used
absolute `/private/tmp` paths, and several missing-asset branches returned
`skipped` even though their quality signals were blocking.

Every pinned manifest now declares one executable materialization contract.
Source builds bind an HTTPS Git repository, exact revision, argument-vector
Maven command, relative work directory, relative artifact path, and expected
SHA-256. Published artifacts bind an HTTPS Maven Central URL, full coordinate,
SHA-1, and SHA-256. `materialize_real_project_asset.py` can review the plan or
execute it without a shell, stores revision/SHA-scoped outputs, and rejects any
checksum mismatch. All seven manifests generated valid plans in the `616df58`
verification run.

Real-project asset, checkout, changed-API, and required-Fat-Jar failures now
produce a failed case with a blocking asset signal. Explicitly omitting the
entire real-project stage remains a quality-gate option and is not represented
as an executed guard.

## Performance Without Scope Loss Finding

Time, memory, javap, and duplicate-scan budgets existed, but a faster run did
not have to prove that it scanned the same API, artifact, class, analyzer-edge,
Oracle-edge, and injected-failure scope. A performance optimization could
therefore improve every timing metric by silently narrowing work.

Relative performance baselines now include a mandatory scope contract. The
shared evaluator rejects any reduction in selected or accounted APIs, artifacts,
classes, analyzer edges, Oracle edges, or detected fault injections. A mutation
that removes one class and one analyzer edge fails even when its elapsed time is
lower. The `616df58` five-project guard satisfied the new scope values with that
commit's envelope schema. It included the 9,413-class RabbitMQ Fat Jar run, all
declared API and edge reconciliation, fault-injection detection, and per-case
performance budgets in the same formal gate execution.

## Canonical Evidence Identity Finding

The audit found four incompatible API identity encodings across Step5, indirect
evidence, exhaustive Oracle reconciliation, and the jdeps ledger. The Oracle
identity also omitted `change_type`, while javap and jdeps mapped one physical
symbol to only one logical change record. These combinations could either split
equivalent source/bytecode spellings or collapse distinct changes on the same
symbol.

All analyzer and Oracle producers now use one shared identity containing exact
coordinate, normalized owner/member name, qualified erased signature, normalized
symbol kind, and change type. Inner-class source and bytecode spellings normalize
equally. A physical javap or jdeps reference is projected to every matching
logical change identity instead of silently retaining only one.

Generalized tests cover equivalent inner-class/generic/varargs spellings,
distinct change types, canonical Envelope targets, one-to-many javap and jdeps
projection, and a mutation that removes `change_type` from third-party evidence.
The mutation must produce missing/extra identities and block the Oracle audit.
