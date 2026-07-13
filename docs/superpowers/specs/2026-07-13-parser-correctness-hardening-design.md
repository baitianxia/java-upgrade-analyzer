# Parser Correctness Hardening Design

## Objective

Repair the confirmed parsing, lifecycle, coverage, and diagnostics defects without weakening existing Step 1, Step 3, or Step 5 evidence. Accuracy remains the primary constraint: a fast path may reject impossible candidates, but it may not replace an authoritative parse when candidate evidence exists.

## Compatibility contract

- Existing exact bytecode and source edges remain valid.
- Direct classfile parsing falls back to the existing `javap` path whenever it cannot prove completeness.
- Parse failures produce incomplete/unavailable evidence, never a negative finding.
- Internal application modules are identified only from build/artifact provenance, never package or group-name guesses.
- Existing user-requested dependency preflight remains, but installation is bounded and isolated from the host Python environment.
- Every defect is reproduced by a test before its implementation is changed; the existing suite remains the regression baseline.

## Architecture

### Classfile facts

Use one bounded classfile reader for constant-pool references, superclass/interfaces, instruction boundaries, method handles, invokedynamic bootstrap targets, and class attributes. Consumers may request a subset of facts. Unsupported or malformed input returns an explicit incomplete result and invokes `javap` where an authoritative fallback exists.

### Runtime dependency scanning

Read class bytes from the already-open archive. Classes whose constant pool contains none of the target owners are skipped without spawning `javap`. Candidate classes use cached full parsing. Cache keys include artifact digest, JDK selection, multi-release entry, and parse capability so a shallow constant-pool result cannot masquerade as a complete bytecode result.

### Fat JAR ownership

Nested `BOOT-INF/lib` and `WEB-INF/lib` artifacts retain their container entry and coordinate. A nested artifact is application-owned only when reactor/build metadata proves it is a selected module artifact. Application-owned nested methods are valid business-path nodes; unproven nested dependencies remain dependency nodes.

### Topology

Read erased superclass and interface names directly from classfile headers. Retain bounded `javap` fallback for unsupported classfiles. Missing hierarchy facts propagate `unknown/incomplete`; they do not become `not assignable`.

### Source and configuration adapters

Java framework adapters consume AST facts where available and use comment/string-masked text only as a declared fallback. MyBatis XML uses an XML parser. Step 3 identifier boundaries include `$`, thread declarations may span lines, and YAML keys are reconstructed with indentation-aware paths.

### Lifecycle and failures

Detached source snapshots are registered and removed with `git worktree remove` before physical cleanup, including failed runs and Step 5 reruns. Worker failures retain exception type, message, artifact, class, and coverage impact. Failed parses are never cached as successful empty parses.

### Tool preflight

Tree-sitter is checked before analysis. Automatic installation uses a tool-owned directory and a bounded timeout. Failure stops at a checkpoint with an explicit accuracy impact; degradation requires explicit user approval.

## Verification

- Focused unit tests for each confirmed defect.
- Real `javac` fixtures for switches, lambdas/method references, generics, inheritance, and inner classes.
- Multi-module Spring Boot nested-JAR fixture proving `business -> internal module -> dependency API` reachability.
- Failure-injection tests for workers, malformed classfiles, timeout, and cleanup.
- Full existing suite plus real-project regression gates.
- Performance counters proving avoided `javap` calls and bounded fallback concurrency.

## Implemented defect mapping

- Constant-pool fast path: direct executable classfile evidence with capability-separated immutable cache; reflection/unresolved dynamic cases retain `javap` fallback.
- Fat Jar internal modules: reactor coordinates from `project_scope` mark only proven nested modules as application-owned.
- Critical swallowed failures: batch and expansion worker failures preserve structured diagnostics and cannot become successful empty parses.
- Multi-module safety net: project-scope tests plus the pinned `gs-multi-module` final-artifact guard cover application-to-nested-module chains.
- Git Worktree leak: dependency snapshots now use `git archive` and never register a worktree.
- Framework parsing: Spring and MyBatis annotation bindings use tree-sitter when available; XML uses ElementTree; masked fallback ignores comments, and dynamic-proxy scanning also ignores literals.
- Tree-sitter installation: bounded installation into a tool-owned directory, with formal checkpoint on failure.
- Topology process flood and deadline cascade: class headers are read directly; fallback remains bounded and incomplete coverage fails closed.
- Generic hierarchy parsing: direct classfile headers use erased exact superclass/interface names.
- Switch and invokedynamic: absolute Code-array padding and BootstrapMethods MethodHandle targets are parsed directly.
- Step 3 source/config parsing: Java `$` identifier boundaries, multiline Thread declarations, and indentation-aware YAML paths.
- Maven dependency parsing: structural coordinate parsing accepts custom scopes, classifiers, optional suffixes, and legacy four-token output.
