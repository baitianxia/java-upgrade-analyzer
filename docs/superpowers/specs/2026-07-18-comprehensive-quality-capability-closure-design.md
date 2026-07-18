# Comprehensive Quality Capability Closure Design

## Goal

Complete the two remaining production capabilities and upgrade testing from a
collection of known examples into a system that actively discovers unknown
correctness, evidence, determinism, resilience, and performance defects.

Completion is capability based. A data model, helper, isolated unit test, or
single passing project is not completion by itself.

## Non-Negotiable Rules

- Analyzer conclusions and Oracle truth remain independently produced.
- Every changed API is reconciled; sampling is forbidden.
- Missing, failed, timed-out, conflicting, or stale evidence fails closed.
- No performance optimization may reduce API, class, edge, archive, or Oracle
  scope.
- Generated and mutated tests use recorded deterministic seeds and emit a
  reproducible fixture on failure.
- No new third-party runtime or test package is required. Generators, mutations,
  classfile inspection, and dependency-boundary checks use the Python standard
  library and the JDK/Maven tools already required by the project.
- A TODO is removed only after its production path, independent Oracle,
  positive and negative tests, mutation detection, real-project guard, and
  release gate all pass.

## Delivery Decomposition

The work is split into three sequential programs. Each program has its own
commits and acceptance gate. Later programs may use evidence produced by earlier
programs, but may not weaken their contracts.

### Program 1: Production Evidence Closure

#### Compile-Time Constant Evidence

Step4 inspects the old dependency classfile and records whether the changed
field has a JVM `ConstantValue` attribute, including a typed normalized value
when available. Step5 inspects every current final-artifact consumer class for
exact `getstatic` or `getfield` links to the canonical owner, field name, and
descriptor. Source references are clues only; they never manufacture a runtime
link.

The resulting evidence record binds old dependency SHA, current final-artifact
SHA, class entry, owner, field, descriptor, extraction method, and completeness.
The single constant-impact adjudicator emits separate compile and runtime
conclusions for deletion, value change, non-constant fields, inlined constants,
retained links, and source/artifact mismatch.

An independent Oracle uses `javap -verbose` and direct classfile inspection. It
must reject missing APIs, extra APIs, wrong descriptors, wrong values, stale
artifacts, and stronger conclusions than the evidence proves. Commons Text is
the mandatory real-project guard.

#### Framework Activation Closure

Framework activation is represented as typed composite evidence, never as an
ordinary static edge. The first closure covers Spring AOP aspects, Spring
Security filter chains, and packaged but unregistered components.

An AOP activation proof requires an application-owned aspect class in the
current final artifact, runtime-visible aspect/component registration evidence,
an exact advice or pointcut identity, and a packaged business join point that
matches under a supported conservative rule. A security filter proof requires
the filter class, bean or chain registration, ordered chain membership, and a
packaged application entry connected to the chain. An unregistered component is
the mandatory negative control and cannot become reachable merely because its
class is packaged.

Every activation edge binds final-artifact SHA and exact resource or class
entries. Unsupported pointcut expressions, conditional registration without a
resolved condition, or incomplete chain order remain `uncertain` with a typed
reason. The Mall Fat JAR is the primary real-project guard, supplemented by
small positive, inactive, and incomplete topologies.

### Program 2: Active Defect Discovery

#### Deterministic Topology Generator

A standard-library generator builds small Maven/Java projects from a topology
model containing module ownership, packaging, API identity, edge kinds,
activation evidence, and expected reachability. Dimensions include same-JAR and
cross-JAR bridges, same coordinates, Fat JAR, WAR, MR-JAR, overloads, bridge
methods, inheritance, interfaces, constants, reflection, proxies, and framework
callbacks.

The generator emits both source/artifacts and an independent truth manifest.
Each generated case runs through the production Step4-to-Step5 output path and
closed-world reconciliation. Fixed seed suites run in CI; failures persist the
seed and minimized topology description.

#### Metamorphic Testing

Semantics-preserving transformations create equivalent variants of a topology:
archive entry reorder, dependency order reorder, module-directory rename,
timestamp changes, unrelated classes, worker-count changes, equivalent bridge
placement, and supported packaging-layout changes. Canonical API conclusions,
physical edge identities, and evidence completeness must remain invariant.
Only explicitly layout-sensitive provenance fields may differ.

#### Production Mutation Testing

An AST-based mutation runner copies selected production modules and applies one
typed mutation at a time: remove edge emission, invert ownership, suppress an
evidence failure, drop a descriptor or coordinate, promote uncertainty, bypass
artifact binding, or skip an archive/class. It then runs the mapped focused
tests and records whether the mutant was killed.

Mutations never alter the working tree and never add switches to production
code. Every enforced capability family declares required production mutants.
A surviving required mutant blocks release and becomes a concrete test gap.

#### Oracle Independence Enforcement

A static dependency-boundary checker parses imports and qualified calls across
analyzer and Oracle modules. Canonical data-only schemas may be shared; parsing,
edge discovery, filtering, and final adjudication implementations may not be
shared. Explicit allowlists are narrow and reviewed by tests. Runtime provenance
records the analyzer producer and Oracle producer for every reconciled fact.

### Program 3: Operational and Performance Assurance

#### Full-Pipeline Fault Injection

Faults extend beyond ledger mutation to subprocess timeout and exit, truncated
stdout, partial CSV/JSON, artifact replacement during scan, permission errors,
encoding variants, interrupted writes, repeated execution, cancellation, and
cache invalidation races. Each fault has one permitted fail-closed state and a
required reason code. No fault may become a normal empty result.

#### Determinism Gate

The same pinned input runs with multiple `PYTHONHASHSEED` values, worker counts,
filesystem enumeration orders, archive orders, and cold/warm caches. A semantic
normalizer removes only documented volatile metadata. Canonical API ledgers,
edge ledgers, status counts, and evidence identities must be byte-identical.

#### Complexity and Resource Gate

Generated scale tiers measure Step1, Step4, and Step5 independently. Metrics
include elapsed time, peak RSS, temporary disk, archive scans, parsed classes,
`javap` invocations, cache hits, and per-API latency. Doubling a controlled input
must stay within a declared ratio as well as an absolute budget. Scope counters
must never decrease to satisfy a budget. Failures identify the responsible
stage and duplicate work key.

#### Platform and Claude Code Contract

GitHub Actions runs the portable contract on Ubuntu, macOS, and Windows, with
the supported JDK matrix where available. Platform tests cover paths, encoding,
process termination, file locking, and command construction.

A clean-checkout contract follows only the public `SKILL.md` workflow and
declared prerequisites. It verifies documented commands, checkpoints, output
locations, failure recovery, and rerun behavior without relying on developer
workspace state. It validates the skill consumed by Claude Code; it does not
test or modify an LLM.

## Evidence and Data Flow

Every capability is registered with:

1. A stable invariant and production entry points.
2. Positive, negative, incomplete, and mutation tests.
3. An independent Oracle producer and provenance digest.
4. Generated or real topology coverage.
5. Determinism and resource expectations where applicable.
6. A release-gate result proving all mandatory checks executed without skips.

The test-round retrospective compares new defects to capability families. A
repeat in an enforced family reopens that family and requires architecture
review rather than another case-specific condition.

## Error Handling

- Generator build failure is a fixture failure, not an analyzer conclusion.
- Oracle failure invalidates truth and blocks reconciliation.
- Mutation infrastructure failure is distinct from a surviving mutant; both
  block mandatory mutation gates.
- Unsupported framework semantics remain typed uncertainty.
- Platform jobs may be excluded only by an explicit documented capability
  constraint; silent skips are forbidden.
- Performance results are invalid if correctness, identity closure, or scope
  counters differ from the baseline.

## Acceptance

Program 1 is complete only when both TODO entries satisfy their full evidence
maps, pass Commons Text and Mall real-project guards, and are removed from
`TODO.md`.

Program 2 is complete only when fixed-seed generated and metamorphic suites pass,
all required production mutants are killed, and the Oracle dependency boundary
has no unapproved violations.

Program 3 is complete only when all registered execution faults are detected,
determinism hashes match across variants, performance ratios and absolute
budgets pass without scope loss, portable CI contracts pass, and the clean
Claude Code workflow produces the expected evidence.

Overall completion requires a fresh full release gate with zero mandatory
skips, zero blocking quality signals, complete capability-family closure, and an
independent code review with no Important or Critical findings.
