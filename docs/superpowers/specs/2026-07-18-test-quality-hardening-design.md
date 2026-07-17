# Test Quality Hardening Design

## Goal

Turn the existing test assets into continuously enforced evidence that the analyzer detects false negatives, false positives, incomplete evidence, performance regressions, and artifact/source mismatches before release.

## Constraints

- Correctness and evidence completeness take priority over runtime.
- No optimization or test mode may reduce API, class, edge, nested-JAR, failure, or Oracle scope.
- Real-project truth must remain independent from analyzer conclusions.
- Required tools and pinned assets fail closed; they never become a passing skip.
- Production behavior changes use failing tests first.
- Existing user changes in the main workspace are outside this branch.

## Architecture

### Enforcement plane

GitHub Actions has three explicit tiers. Pull requests run the quick gate and tool preflight. Pushes to `main` run the Step5 gate without silently skipping required tools. A scheduled/manual release workflow runs the full release gate and pinned real-project guard matrix. Workflow path filters include every behavior-bearing path, including `references/**`.

The gate emits a machine-readable result even after failures. Required tool absence, skipped mandatory tasks, missing result artifacts, and stale pinned assets block the gate.

### Mutation plane

Fault injection is a registry of typed mutations rather than a single special case. Mutations cover a missing analyzer edge, an extra analyzer edge, a wrong descriptor, a changed Oracle file, and an incomplete Oracle scan. Every mutation declares the quality signal it must trigger. Oracle evidence hashes must remain stable for analyzer-only mutations.

Mutations operate on copied ledgers in the test orchestration layer. Production Step5 contains no mutation switches.

### Evidence-state plane

Evidence transition tests define monotonic state changes for `uncertain`: removing required evidence may downgrade a conclusion; adding authoritative evidence may upgrade it; unrelated evidence may not change it. The transition matrix is keyed by reason code and canonical API identity.

Compile-time constants carry separate compile and runtime impact dimensions. Artifact alignment records bind Git revision, dirty state, target module, build command/profile, and artifact SHA-256. Framework activation evidence binds registration resources or bytecode annotations to the final artifact SHA.

### Capability plane

The topology registry expands with Spring AOP, security filter-chain, inactive component, event/callback, WAR layout, multi-release selection, and mixed Kotlin/Java identities. Each topology has positive, negative, and incomplete-evidence expectations and an independent Oracle procedure.

### Resilience and performance plane

Generated artifacts exercise malformed class files, unsafe ZIP entries, excessive expansion ratios, nested depth, and duplicate classes. End-to-end stress fixtures preserve scope counters while enforcing elapsed time, peak RSS, parser invocations, and duplicate scan budgets. Cold and warm cache runs must return byte-identical semantic ledgers.

## Delivery order

1. CI and tool/skip enforcement.
2. Typed real-project fault injection.
3. Artifact alignment and compile-time constant evidence.
4. Framework activation and uncertain transition matrices.
5. WAR, MR-JAR, Kotlin/JDK, hostile artifact, and stress coverage.
6. Full release gate and pinned real-project verification.

## Acceptance

- CI configuration tests prove behavior-bearing changes trigger a gate and required tools cannot skip.
- Each mutation is observed failing before implementation and then triggers its required blocking signal.
- The three open TODO capability items have executable positive, negative, and incomplete-evidence tests and are removed from `TODO.md` only after implementation and verification.
- New topology fixtures are registered and covered by topology closure.
- Release verification passes without skipped mandatory tasks and without reducing the registered scope baselines.

