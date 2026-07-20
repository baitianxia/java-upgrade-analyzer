# Quality Convergence Design

## Goal

Stop project-by-project patching and converge the analyzer around explicit invariants that prevent false negatives, false positives, self-certified Oracle results, and performance regressions.

## Scope Freeze

- Do not add another real project until the current Pig case passes every correctness and performance gate.
- Do not add new analyzer capabilities while a Critical or Important review finding remains open.
- Do not relax a threshold or downgrade a blocking result to make a run pass.
- Do not merge until a fresh full run, full unit suite, fault injection, and independent review all pass on the same tree.

## Invariants

### Call Graph

- Analysis of one API must not delete or rewrite evidence collected for another API.
- Results must be independent of API processing order and cold/warm cache state.
- Only an exact method self-call may be excluded as recursion. Calls between different methods in the same class are real internal bridges.
- Single-API, batch, and reverse-closure paths must share the same edge-admission predicate.

### Artifact Ownership

- Reactor ownership is derived from the effective active Maven model, not every profile declared in a POM.
- A nested Fat Jar entry is application-owned only when final-artifact identity and the active reactor closure prove it.
- Source directories and stale target classes are never runtime evidence for a packaged-artifact conclusion.

### Oracle Trust Boundary

- Every evidence file must exist and its bytes must match the declared SHA-256 at audit time.
- Every edge or reference must carry the locked artifact SHA; a correct top-level SHA cannot cover an unbound child record.
- Authority names do not establish independence. Negative conclusions are accepted only from declared evidence capabilities with closed-world coverage, executable semantics, and artifact binding, or from genuinely independent supporting authorities.
- Constant-pool membership is diagnostic evidence and cannot prove executable reachability or executable absence.

### Test Integrity

- Every defect begins with a minimal failing regression that demonstrates the incorrect externally visible conclusion.
- Each root-cause fix includes equivalence tests for all implementation paths and a counterexample that would fail under the old behavior.
- Fault injection must prove that a mutation changed the evidence before detection is credited.
- Three related failures in adjacent branches stop local patching and trigger redesign of that subsystem.

## Convergence Sequence

1. Repair graph immutability and exact self-recursion handling.
2. Repair Oracle file, digest, child-record, and authority-capability validation.
3. Repair active-profile ownership and Fat Jar internal-module path handling.
4. Repair ineffective fault injection.
5. Remove performance regressions without reducing evidence coverage.
6. Run Pig 804/804, full tests, static checks, and independent review on one unchanged tree.

## Completion Contract

The branch is complete only when all listed findings have a failing-before/passing-after regression, Pig reports 804 verified APIs with zero incorrect/conflict/unverified results, all five fault injections are effective and detected, relative performance passes, the full suite passes, and an independent reviewer reports no Critical or Important findings.
